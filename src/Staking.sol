// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "openzeppelin-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlEnumerableUpgradeable} from
    "openzeppelin-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import {Math} from "openzeppelin/utils/math/Math.sol";
import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";
import {SafeERC20Upgradeable} from "openzeppelin-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";

import {ProtocolEvents} from "./interfaces/ProtocolEvents.sol";
import {IDepositContract} from "./interfaces/IDepositContract.sol";
import {IMETH} from "./interfaces/IMETH.sol";
import {IOracleReadRecord, OracleRecord} from "./interfaces/IOracle.sol";
import {IPauserRead} from "./interfaces/IPauser.sol";
import {IStaking, IStakingReturnsWrite, IStakingInitiationRead} from "./interfaces/IStaking.sol";
import {UnstakeRequest, IUnstakeRequestsManager} from "./interfaces/IUnstakeRequestsManager.sol";

/// @notice Events emitted by the staking contract.
interface StakingEvents {
    /// @notice Emitted when a user stakes ETH and receives mETH.
    /// @param staker The address of the user staking ETH.
    /// @param ethAmount The amount of ETH staked.
    /// @param mETHAmount The amount of mETH received.
    event Staked(address indexed staker, uint256 ethAmount, uint256 mETHAmount);

    /// @notice Emitted when a user unstakes mETH in exchange for ETH.
    /// @param id The ID of the unstake request.
    /// @param staker The address of the user unstaking mETH.
    /// @param ethAmount The amount of ETH that the staker will receive.
    /// @param mETHLocked The amount of mETH that will be burned.
    event UnstakeRequested(uint256 indexed id, address indexed staker, uint256 ethAmount, uint256 mETHLocked);

    /// @notice Emitted when a user claims their unstake request.
    /// @param id The ID of the unstake request.
    /// @param staker The address of the user claiming their unstake request.
    event UnstakeRequestClaimed(uint256 indexed id, address indexed staker);

    /// @notice Emitted when a validator has been initiated (i.e. the protocol has deposited into the deposit contract).
    /// @param id The ID of the validator which is the hash of its pubkey.
    /// @param operatorID The ID of the node operator to which the validator belongs to.
    /// @param pubkey The pubkey of the validator.
    /// @param amountDeposited The amount of ETH deposited into the deposit contract for that validator.
    event ValidatorInitiated(bytes32 indexed id, uint256 indexed operatorID, bytes pubkey, uint256 amountDeposited);

    /// @notice Emitted when the protocol has allocated ETH to the UnstakeRequestsManager.
    /// @param amount The amount of ETH allocated to the UnstakeRequestsManager.
    event AllocatedETHToUnstakeRequestsManager(uint256 amount);

    /// @notice Emitted when the protocol has allocated ETH to use for deposits into the deposit contract.
    /// @param amount The amount of ETH allocated to deposits.
    event AllocatedETHToDeposits(uint256 amount);

    /// @notice Emitted when the protocol has received returns from the returns aggregator.
    /// @param amount The amount of ETH received.
    event ReturnsReceived(uint256 amount);
}

// 核心概念，用户存入 ETH 获取 mETH 代币，当前协议将 ETH 发送给验证器进行质押获取收益
contract Staking is Initializable, AccessControlEnumerableUpgradeable, IStaking, StakingEvents, ProtocolEvents {
    // Errors.
    error DoesNotReceiveETH();
    error InvalidConfiguration();
    error MaximumValidatorDepositExceeded();
    error MaximumMETHSupplyExceeded();
    error MinimumStakeBoundNotSatisfied();
    error MinimumUnstakeBoundNotSatisfied();
    error MinimumValidatorDepositNotSatisfied();
    error NotEnoughDepositETH();
    error NotEnoughUnallocatedETH();
    error NotReturnsAggregator();
    error NotUnstakeRequestsManager();
    error Paused();
    error PreviouslyUsedValidator();
    error ZeroAddress();
    error InvalidDepositRoot(bytes32);
    error StakeBelowMinimumMETHAmount(uint256 methAmount, uint256 expectedMinimum);
    error UnstakeBelowMinimumETHAmount(uint256 ethAmount, uint256 expectedMinimum);

    error InvalidWithdrawalCredentialsWrongLength(uint256);
    error InvalidWithdrawalCredentialsNotETH1(bytes12);
    error InvalidWithdrawalCredentialsWrongAddress(address);

    // 角色权限定义
    bytes32 public constant STAKING_MANAGER_ROLE = keccak256("STAKING_MANAGER_ROLE");  // 质押管理员角色
    bytes32 public constant ALLOCATOR_SERVICE_ROLE = keccak256("ALLOCATER_SERVICE_ROLE");     // 资金分配管理员角色
    bytes32 public constant INITIATOR_SERVICE_ROLE = keccak256("INITIATOR_SERVICE_ROLE");   // 验证器启动员角色

    /// @notice Role to manage the staking allowlist.
    bytes32 public constant STAKING_ALLOWLIST_MANAGER_ROLE = keccak256("STAKING_ALLOWLIST_MANAGER_ROLE");

    /// @notice Role allowed to stake ETH when allowlist is enabled.
    bytes32 public constant STAKING_ALLOWLIST_ROLE = keccak256("STAKING_ALLOWLIST_ROLE");

    /// @notice Role allowed to top up the unallocated ETH in the protocol.
    bytes32 public constant TOP_UP_ROLE = keccak256("TOP_UP_ROLE");

    /// @notice Payload struct submitted for validator initiation.
    /// @dev See also {initiateValidatorsWithDeposits}.
    struct ValidatorParams {
        uint256 operatorID;
        uint256 depositAmount;
        bytes pubkey;
        bytes withdrawalCredentials;
        bytes signature;
        bytes32 depositDataRoot;
    }

    /// @notice Keeps track of already initiated validators.
    /// @dev This is tracked to ensure that we never deposit for the same validator public key twice, which is a base
    /// assumption of this contract and the related off-chain accounting.
    mapping(bytes pubkey => bool exists) public usedValidators;

    // 资金池状态
    uint256 public unallocatedETH;                 // 未分配的 ETH，用户质押但还未分配用途的ETH
    uint256 public allocatedETHForDeposits;        // 已分配用于启动验证器的 ETH
    uint256 public totalDepositedInValidators;     // 已发送给验证器的ETH总量
    uint256 public numInitiatedValidators;         // 已启动的验证器数量

    uint256 public minimumStakeBound;              // 用户质押 ETH 的最小数量
    uint256 public minimumUnstakeBound;            // 用户解质押 mETH 的最小数量

    // 汇率调整机制（重要！）
    uint16 public exchangeAdjustmentRate;          // 汇率调整率，用于补偿以太坊2.0进入和退出队列时间差

    /// @dev A basis point (often denoted as bp, 1bp = 0.01%) is a unit of measure used in finance to describe
    /// the percentage change in a financial instrument. This is a constant value set as 10000 which represents
    /// 100% in basis point terms.
    uint16 internal constant _BASIS_POINTS_DENOMINATOR = 10_000;

    /// @notice The maximum amount the exchange adjustment rate (10%) that can be set by the admin.
    uint16 internal constant _MAX_EXCHANGE_ADJUSTMENT_RATE = _BASIS_POINTS_DENOMINATOR / 10; // 10%

    /// @notice The minimum amount of ETH that the staking contract can send to the deposit contract to initiate new
    /// validators.
    /// @dev This is used as an additional safeguard to prevent sending deposits that would result in non-activated
    /// validators (since we don't do top-ups), that would need to be exited again to get the ETH back.
    uint256 public minimumDepositAmount;

    /// @notice The maximum amount of ETH that the staking contract can send to the deposit contract to initiate new
    /// validators.
    /// @dev This is used as an additional safeguard to prevent sending too large deposits. While this is not a critical
    /// issue as any surplus >32 ETH (at the time of writing) will automatically be withdrawn again at some point, it is
    /// still undesireable as it locks up not-earning ETH for the duration of the round trip decreasing the efficiency
    /// of the protocol.
    uint256 public maximumDepositAmount;

    /// @notice The beacon chain deposit contract.
    /// @dev ETH will be sent there during validator initiation.
    IDepositContract public depositContract;

    /// @notice The mETH token contract.
    /// @dev Tokens will be minted / burned during staking / unstaking.
    IMETH public mETH;

    /// @notice The oracle contract.
    /// @dev Tracks ETH on the beacon chain and other accounting relevant quantities.
    IOracleReadRecord public oracle;

    /// @notice The pauser contract.
    /// @dev Keeps the pause state across the protocol.
    IPauserRead public pauser;

    /// @notice The contract tracking unstake requests and related allocation and claim operations.
    IUnstakeRequestsManager public unstakeRequestsManager;

    /// @notice The address to receive beacon chain withdrawals (i.e. validator rewards and exits).
    /// @dev Changing this variable will not have an immediate effect as all exisiting validators will still have the
    /// original value set.
    address public withdrawalWallet;

    /// @notice The address for the returns aggregator contract to push funds.
    /// @dev See also {receiveReturns}.
    address public returnsAggregator;

    /// @notice The staking allowlist flag which, when enabled, allows staking only for addresses in allowlist.
    bool public isStakingAllowlist;

    /// @inheritdoc IStakingInitiationRead
    /// @dev This will be used to give off-chain services a sensible point in time to start their analysis from.
    uint256 public initializationBlockNumber;

    /// @notice The maximum amount of mETH that can be minted during the staking process.
    /// @dev This is used as an additional safeguard to create a maximum stake amount in the protocol. As the protocol
    /// scales up this value will be increased to allow for more staking.
    uint256 public maximumMETHSupply;

    /// @notice Configuration for contract initialization.
    struct Init {
        address admin;
        address manager;
        address allocatorService;
        address initiatorService;
        address returnsAggregator;
        address withdrawalWallet;
        IMETH mETH;
        IDepositContract depositContract;
        IOracleReadRecord oracle;
        IPauserRead pauser;
        IUnstakeRequestsManager unstakeRequestsManager;
    }

    constructor() {
        _disableInitializers();
    }

    /// @notice Inititalizes the contract.
    /// @dev MUST be called during the contract upgrade to set up the proxies state.
    function initialize(Init memory init) external initializer {
        __AccessControlEnumerable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, init.admin);
        _grantRole(STAKING_MANAGER_ROLE, init.manager);
        _grantRole(ALLOCATOR_SERVICE_ROLE, init.allocatorService);
        _grantRole(INITIATOR_SERVICE_ROLE, init.initiatorService);
        // Intentionally does not set anyone as the TOP_UP_ROLE as it will only be granted
        // in the off-chance that the top up functionality is required.

        // Set up roles for the staking allowlist. Intentionally do not grant anyone the
        // STAKING_ALLOWLIST_MANAGER_ROLE as it will only be granted later.
        _setRoleAdmin(STAKING_ALLOWLIST_MANAGER_ROLE, STAKING_MANAGER_ROLE);
        _setRoleAdmin(STAKING_ALLOWLIST_ROLE, STAKING_ALLOWLIST_MANAGER_ROLE);

        mETH = init.mETH;
        depositContract = init.depositContract;
        oracle = init.oracle;
        pauser = init.pauser;
        returnsAggregator = init.returnsAggregator;
        unstakeRequestsManager = init.unstakeRequestsManager;
        withdrawalWallet = init.withdrawalWallet;

        minimumStakeBound = 0.1 ether;
        minimumUnstakeBound = 0.01 ether;
        minimumDepositAmount = 32 ether;
        maximumDepositAmount = 32 ether;
        isStakingAllowlist = true;
        initializationBlockNumber = block.number;

        // Set the maximum mETH supply to some sensible amount which is expected to be changed as the
        // protocol ramps up.
        maximumMETHSupply = 1024 ether;
    }

    /**
     * 用户质押ETH换取mETH代币
     * @param minMETHAmount 用户期望获得的最少mETH数量（防滑点保护）
     *
     * 执行逻辑：
     * 1. 检查是否暂停、白名单权限、最小质押金额
     * 2. 计算能获得的mETH数量（考虑汇率调整）
     * 3. 检查是否超过最大mETH供应量限制
     * 4. 将ETH添加到未分配资金池
     * 5. 铸造mETH给用户
     */
    function stake(uint256 minMETHAmount) external payable {
        // 暂停检查
        if (pauser.isStakingPaused()) {
            revert Paused();
        }

        // 白名单检查（如果启用）
        if (isStakingAllowlist) {
            _checkRole(STAKING_ALLOWLIST_ROLE);
        }

        // 最小金额检查
        if (msg.value < minimumStakeBound) {
            revert MinimumStakeBoundNotSatisfied();
        }

        //!! 汇率计算 - 这里非常重要
        uint256 mETHMintAmount = ethToMETH(msg.value);

        // 供给量检查
        if (mETHMintAmount + mETH.totalSupply() > maximumMETHSupply) {
            revert MaximumMETHSupplyExceeded();
        }

        // 滑点保护
        if (mETHMintAmount < minMETHAmount) {
            revert StakeBelowMinimumMETHAmount(mETHMintAmount, minMETHAmount);
        }

        // Increment unallocated ETH after calculating the exchange rate to ensure a consistent rate.
        // 先计算汇率再更新余额，确保汇率一致性
        unallocatedETH += msg.value;

        emit Staked(msg.sender, msg.value, mETHMintAmount);
        mETH.mint(msg.sender, mETHMintAmount);
    }

    /**
     * 用户提交解质押请求（注意：不是立即解质押！）
     * @param methAmount 要解质押的mETH数量
     * @param minETHAmount 期望获得的最少ETH数量
     * @return 请求ID
     */
    function unstakeRequest(uint128 methAmount, uint128 minETHAmount) external returns (uint256) {
        return _unstakeRequest(methAmount, minETHAmount);
    }

    /// @notice Interface for users to submit a request to unstake with an ERC20 permit.
    /// @dev Transfers the specified amount of mETH to the staking contract and locks it there until it is burned on
    /// request claim. The permit must therefore allow the staking contract to move the user's mETH on their behalf.
    /// @return The request ID.
    function unstakeRequestWithPermit(
        uint128 methAmount,
        uint128 minETHAmount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (uint256) {
        SafeERC20Upgradeable.safePermit(mETH, msg.sender, address(this), methAmount, deadline, v, r, s);
        return _unstakeRequest(methAmount, minETHAmount);
    }

    /**
     * 执行逻辑：
     * 1. 检查暂停状态和最小解质押金额
     * 2. 计算能获得的ETH数量
     * 3. 在 UnstakeRequestsManager 中创建请求
     * 4. 将 mETH 转移到 UnstakeRequestsManager 锁定
     */
    function _unstakeRequest(uint128 methAmount, uint128 minETHAmount) internal returns (uint256) {
        if (pauser.isUnstakeRequestsAndClaimsPaused()) {
            revert Paused();
        }

        if (methAmount < minimumUnstakeBound) {
            revert MinimumUnstakeBoundNotSatisfied();
        }

        // 汇率计算
        uint128 ethAmount = uint128(mETHToETH(methAmount));

        // 滑点保护
        if (ethAmount < minETHAmount) {
            revert UnstakeBelowMinimumETHAmount(ethAmount, minETHAmount);
        }

        // 创建请求
        uint256 requestID = unstakeRequestsManager.create({
            requester: msg.sender,
            mETHLocked: methAmount,
            ethRequested: ethAmount
        });

        emit UnstakeRequested({id: requestID, staker: msg.sender, ethAmount: ethAmount, mETHLocked: methAmount});

        // 将 mETH 锁定到请求管理器
        SafeERC20Upgradeable.safeTransferFrom(mETH, msg.sender, address(unstakeRequestsManager), methAmount);

        return requestID;
    }

    /// @notice Interface for users to claim their finalized and filled unstaking requests.
    /// @dev See also {UnstakeRequestsManager} for a more detailed explanation of finalization and request filling.
    function claimUnstakeRequest(uint256 unstakeRequestID) external {
        if (pauser.isUnstakeRequestsAndClaimsPaused()) {
            revert Paused();
        }
        emit UnstakeRequestClaimed(unstakeRequestID, msg.sender);
        unstakeRequestsManager.claim(unstakeRequestID, msg.sender);
    }

    /// @notice Returns the status of the request whether it is finalized and how much ETH has been filled.
    /// See also {UnstakeRequestsManager.requestInfo} for a more detailed explanation of finalization and request
    /// filling.
    /// @param unstakeRequestID The ID of the unstake request.
    /// @return bool indicating if the unstake request is finalized, and the amount of ETH that has been filled.
    function unstakeRequestInfo(uint256 unstakeRequestID) external view returns (bool, uint256) {
        return unstakeRequestsManager.requestInfo(unstakeRequestID);
    }

    /// @notice Withdraws any surplus from the unstake requests manager.
    /// @dev The request manager is expected to return the funds by pushing them using
    /// {receiveFromUnstakeRequestsManager}.
    function reclaimAllocatedETHSurplus() external onlyRole(STAKING_MANAGER_ROLE) {
        // Calls the receiveFromUnstakeRequestsManager() where we perform
        // the accounting.
        unstakeRequestsManager.withdrawAllocatedETHSurplus();
    }

    /**
     * 将未分配的ETH分配到两个用途：解质押请求和验证器启动
     * @param allocateToUnstakeRequestsManager 分配给解质押请求的ETH
     * @param allocateToDeposits 分配给验证器启动的ETH
     *
     * 这个函数很重要！它管理着协议的资金流向：
     * - 用户质押的ETH首先进入unallocatedETH池
     * - 通过这个函数将资金分配到具体用途
     * - 保证资金既能满足用户解质押，又能启动新验证器获得收益
     */
    function allocateETH(uint256 allocateToUnstakeRequestsManager, uint256 allocateToDeposits) external onlyRole(ALLOCATOR_SERVICE_ROLE) {
        if (pauser.isAllocateETHPaused()) {
            revert Paused();
        }

        // 检查是否有足够的未分配 ETH
        if (allocateToUnstakeRequestsManager + allocateToDeposits > unallocatedETH) {
            revert NotEnoughUnallocatedETH();
        }

        // 从未分配池中扣除
        unallocatedETH -= allocateToUnstakeRequestsManager + allocateToDeposits;

        // 分配给验证器启动
        if (allocateToDeposits > 0) {
            allocatedETHForDeposits += allocateToDeposits;
            emit AllocatedETHToDeposits(allocateToDeposits);
        }

        // 分配给解质押管理器并立即发送ETH
        if (allocateToUnstakeRequestsManager > 0) {
            emit AllocatedETHToUnstakeRequestsManager(allocateToUnstakeRequestsManager);
            unstakeRequestsManager.allocateETH{value: allocateToUnstakeRequestsManager}();
        }
    }

    /*
     * 启动新验证器，将ETH发送到以太坊存款合约
     * @param validators 验证器参数数组
     * @param expectedDepositRoot 期望的存款根（防MEV攻击）
     *
     * 这是协议获得收益的关键步骤！
     * 将分配的ETH发送给以太坊2.0验证器开始质押
     */
    function initiateValidatorsWithDeposits(ValidatorParams[] calldata validators, bytes32 expectedDepositRoot) external onlyRole(INITIATOR_SERVICE_ROLE) {
        if (pauser.isInitiateValidatorsPaused()) {
            revert Paused();
        }
        if (validators.length == 0) {
            return;
        }

        // 防止MEV攻击：检查存款根是否匹配
        bytes32 actualRoot = depositContract.get_deposit_root();
        if (expectedDepositRoot != actualRoot) {
            revert InvalidDepositRoot(actualRoot);
        }

        uint256 amountDeposited = 0;

        // 第一轮循环：验证所有验证器参数并记录
        for (uint256 i = 0; i < validators.length; ++i) {
            ValidatorParams calldata validator = validators[i];

            // 防止重复启动同一个验证器
            if (usedValidators[validator.pubkey]) {
                revert PreviouslyUsedValidator();
            }

            // 检查存款金额范围
            if (validator.depositAmount < minimumDepositAmount) {
                revert MinimumValidatorDepositNotSatisfied();
            }

            if (validator.depositAmount > maximumDepositAmount) {
                revert MaximumValidatorDepositExceeded();
            }

            // 验证提取凭证必须指向协议钱包
            _requireProtocolWithdrawalAccount(validator.withdrawalCredentials);

            // 标记为已使用并累计金额
            usedValidators[validator.pubkey] = true;
            amountDeposited += validator.depositAmount;

            emit ValidatorInitiated({
                id: keccak256(validator.pubkey),
                operatorID: validator.operatorID,
                pubkey: validator.pubkey,
                amountDeposited: validator.depositAmount
            });
        }

        // 检查是否有足够的已分配ETH
        if (amountDeposited > allocatedETHForDeposits) {
            revert NotEnoughDepositETH();
        }

        // 更新状态变量
        allocatedETHForDeposits -= amountDeposited;
        totalDepositedInValidators += amountDeposited;
        numInitiatedValidators += validators.length;

        // 第二轮循环：向存款合约发送ETH（分离状态更新和外部调用）
        for (uint256 i = 0; i < validators.length; ++i) {
            ValidatorParams calldata validator = validators[i];
            depositContract.deposit{value: validator.depositAmount}({
                pubkey: validator.pubkey,
                withdrawal_credentials: validator.withdrawalCredentials,
                signature: validator.signature,
                deposit_data_root: validator.depositDataRoot
            });
        }
    }

    /// @inheritdoc IStakingReturnsWrite
    /// @dev Intended to be the called in the same transaction initiated by reclaimAllocatedETHSurplus().
    /// This should only be called in emergency scenarios, e.g. if the unstake requests manager has cancelled
    /// unfinalized requests and there is a surplus balance.
    /// Adds the received funds to the unallocated balance.
    function receiveFromUnstakeRequestsManager() external payable onlyUnstakeRequestsManager {
        unallocatedETH += msg.value;
    }

    /// @notice Tops up the unallocated ETH balance to increase the amount of ETH in the protocol.
    /// @dev Bypasses the returns aggregator fee collection to inject ETH directly into the protocol.
    function topUp() external payable onlyRole(TOP_UP_ROLE) {
        unallocatedETH += msg.value;
    }

    /*
     * ETH转mETH汇率计算（质押时使用）
     * 这里包含了协议的核心创新：汇率调整机制！
     */
    function ethToMETH(uint256 ethAmount) public view returns (uint256) {
        // 首次质押时 1:1 汇率
        if (mETH.totalSupply() == 0) {
            return ethAmount;
        }

        // 核心公式：deltaMETH = (1 - exchangeAdjustmentRate) * (mETHSupply / totalControlled) * ethAmount
        //
        // 这里的exchangeAdjustmentRate是关键创新：
        // - 以太坊2.0进入队列约40天（无收益）
        // - 退出队列约6天（有收益）
        // - 为了防止"快进快出"攻击，质押时给予约35天收益的折扣
        // - 这保护了协议和现有质押者的利益
        return Math.mulDiv(
            ethAmount,
            mETH.totalSupply() * uint256(_BASIS_POINTS_DENOMINATOR - exchangeAdjustmentRate),
            totalControlled() * uint256(_BASIS_POINTS_DENOMINATOR)
        );
    }

    /*
     * mETH转ETH汇率计算（解质押时使用）
     * 注意：解质押时不应用调整率，按实际价值计算
     */
    function mETHToETH(uint256 mETHAmount) public view returns (uint256) {
        // 1:1 exchange rate on the first stake.
        if (mETH.totalSupply() == 0) {
            return mETHAmount;
        }

        // 简单公式：deltaETH = (totalControlled / mETHSupply) * mETHAmount
        return Math.mulDiv(mETHAmount, totalControlled(), mETH.totalSupply());
    }

    /*
     * 计算协议控制的 ETH 总量
     * 这是汇率计算的基础，必须准确反映所有ETH的分布状态
     */
    function totalControlled() public view returns (uint256) {
        OracleRecord memory record = oracle.latestRecord();
        uint256 total = 0;

        // 1. 未分配的ETH（用户质押还未分配用途）
        total += unallocatedETH;

        // 2. 已分配给验证器启动但还未发送的ETH
        total += allocatedETHForDeposits;

        // 3. 已发送但还未被Oracle处理的ETH（在途资金）
        // 注意：要减去Oracle已处理的部分避免重复计算
        total += totalDepositedInValidators - record.cumulativeProcessedDepositAmount;

        // 4. Oracle报告的验证器余额（包含本金+收益）
        total += record.currentTotalValidatorBalance;

        // 5. 解质押请求管理器中的ETH
        total += unstakeRequestsManager.balance();
        return total;
    }

    /// @notice Checks if the given withdrawal credentials are a valid 0x01 prefixed withdrawal address.
    /// @dev See also
    /// https://github.com/ethereum/consensus-specs/blob/master/specs/phase0/validator.md#eth1_address_withdrawal_prefix
    function _requireProtocolWithdrawalAccount(bytes calldata withdrawalCredentials) internal view {
        if (withdrawalCredentials.length != 32) {
            revert InvalidWithdrawalCredentialsWrongLength(withdrawalCredentials.length);
        }

        // Check the ETH1_ADDRESS_WITHDRAWAL_PREFIX and that all other bytes are zero.
        bytes12 prefixAndPadding = bytes12(withdrawalCredentials[:12]);
        if (prefixAndPadding != 0x010000000000000000000000) {
            revert InvalidWithdrawalCredentialsNotETH1(prefixAndPadding);
        }

        address addr = address(bytes20(withdrawalCredentials[12:32]));
        if (addr != withdrawalWallet) {
            revert InvalidWithdrawalCredentialsWrongAddress(addr);
        }
    }

    /// @inheritdoc IStakingReturnsWrite
    /// @dev Adds the received funds to the unallocated balance.
    function receiveReturns() external payable onlyReturnsAggregator {
        emit ReturnsReceived(msg.value);
        unallocatedETH += msg.value;
    }

    /// @notice Ensures that the caller is the returns aggregator.
    modifier onlyReturnsAggregator() {
        if (msg.sender != returnsAggregator) {
            revert NotReturnsAggregator();
        }
        _;
    }

    /// @notice Ensures that the caller is the unstake requests manager.
    modifier onlyUnstakeRequestsManager() {
        if (msg.sender != address(unstakeRequestsManager)) {
            revert NotUnstakeRequestsManager();
        }
        _;
    }

    /// @notice Ensures that the given address is not the zero address.
    modifier notZeroAddress(address addr) {
        if (addr == address(0)) {
            revert ZeroAddress();
        }
        _;
    }

    /// @notice Sets the minimum amount of ETH users can stake.
    function setMinimumStakeBound(uint256 minimumStakeBound_) external onlyRole(STAKING_MANAGER_ROLE) {
        minimumStakeBound = minimumStakeBound_;
        emit ProtocolConfigChanged(
            this.setMinimumStakeBound.selector, "setMinimumStakeBound(uint256)", abi.encode(minimumStakeBound_)
        );
    }

    /// @notice Sets the minimum amount of mETH users can unstake.
    function setMinimumUnstakeBound(uint256 minimumUnstakeBound_) external onlyRole(STAKING_MANAGER_ROLE) {
        minimumUnstakeBound = minimumUnstakeBound_;
        emit ProtocolConfigChanged(
            this.setMinimumUnstakeBound.selector, "setMinimumUnstakeBound(uint256)", abi.encode(minimumUnstakeBound_)
        );
    }

    /// @notice Sets the staking adjust rate.
    function setExchangeAdjustmentRate(uint16 exchangeAdjustmentRate_) external onlyRole(STAKING_MANAGER_ROLE) {
        if (exchangeAdjustmentRate_ > _MAX_EXCHANGE_ADJUSTMENT_RATE) {
            revert InvalidConfiguration();
        }

        // even though this check is redundant with the one above, this function will be rarely used so we keep it as a
        // reminder for future upgrades that this must never be violated.
        assert(exchangeAdjustmentRate_ <= _BASIS_POINTS_DENOMINATOR);

        exchangeAdjustmentRate = exchangeAdjustmentRate_;
        emit ProtocolConfigChanged(
            this.setExchangeAdjustmentRate.selector,
            "setExchangeAdjustmentRate(uint16)",
            abi.encode(exchangeAdjustmentRate_)
        );
    }

    /// @notice Sets the minimum amount of ETH that the staking contract can send to the deposit contract to initiate
    /// new validators.
    function setMinimumDepositAmount(uint256 minimumDepositAmount_) external onlyRole(STAKING_MANAGER_ROLE) {
        minimumDepositAmount = minimumDepositAmount_;
        emit ProtocolConfigChanged(
            this.setMinimumDepositAmount.selector, "setMinimumDepositAmount(uint256)", abi.encode(minimumDepositAmount_)
        );
    }

    /// @notice Sets the maximum amount of ETH that the staking contract can send to the deposit contract to initiate
    /// new validators.
    function setMaximumDepositAmount(uint256 maximumDepositAmount_) external onlyRole(STAKING_MANAGER_ROLE) {
        maximumDepositAmount = maximumDepositAmount_;
        emit ProtocolConfigChanged(
            this.setMaximumDepositAmount.selector, "setMaximumDepositAmount(uint256)", abi.encode(maximumDepositAmount_)
        );
    }

    /// @notice Sets the maximumMETHSupply variable.
    /// Note: We intentionally allow this to be set lower than the current totalSupply so that the amount can be
    /// adjusted downwards by unstaking.
    /// See also {maximumMETHSupply}.
    function setMaximumMETHSupply(uint256 maximumMETHSupply_) external onlyRole(STAKING_MANAGER_ROLE) {
        maximumMETHSupply = maximumMETHSupply_;
        emit ProtocolConfigChanged(
            this.setMaximumMETHSupply.selector, "setMaximumMETHSupply(uint256)", abi.encode(maximumMETHSupply_)
        );
    }

    /// @notice Sets the address to receive beacon chain withdrawals (i.e. validator rewards and exits).
    /// @dev Changing this variable will not have an immediate effect as all exisiting validators will still have the
    /// original value set.
    function setWithdrawalWallet(address withdrawalWallet_)
        external
        onlyRole(STAKING_MANAGER_ROLE)
        notZeroAddress(withdrawalWallet_)
    {
        withdrawalWallet = withdrawalWallet_;
        emit ProtocolConfigChanged(
            this.setWithdrawalWallet.selector, "setWithdrawalWallet(address)", abi.encode(withdrawalWallet_)
        );
    }

    /// @notice Sets the staking allowlist flag.
    function setStakingAllowlist(bool isStakingAllowlist_) external onlyRole(STAKING_MANAGER_ROLE) {
        isStakingAllowlist = isStakingAllowlist_;
        emit ProtocolConfigChanged(
            this.setStakingAllowlist.selector, "setStakingAllowlist(bool)", abi.encode(isStakingAllowlist_)
        );
    }

    receive() external payable {
        revert DoesNotReceiveETH();
    }

    fallback() external payable {
        revert DoesNotReceiveETH();
    }
}
