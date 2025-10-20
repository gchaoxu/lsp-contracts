// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "openzeppelin-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlEnumerableUpgradeable} from "openzeppelin-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import {Address} from "openzeppelin/utils/Address.sol";
import {Math} from "openzeppelin/utils/math/Math.sol";
import {SafeERC20Upgradeable} from "openzeppelin-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";

import {ProtocolEvents} from "./interfaces/ProtocolEvents.sol";
import {IMETH} from "./interfaces/IMETH.sol";
import {IOracleReadRecord} from "./interfaces/IOracle.sol";
import {
    IUnstakeRequestsManager,
    IUnstakeRequestsManagerWrite,
    IUnstakeRequestsManagerRead,
    UnstakeRequest
} from "./interfaces/IUnstakeRequestsManager.sol";
import {IStakingReturnsWrite} from "./interfaces/IStaking.sol";

/// @notice Events emitted by the unstake requests manager.
interface UnstakeRequestsManagerEvents {
    /// @notice Created emitted when an unstake request has been created.
    /// @param id The id of the unstake request.
    /// @param requester The address of the user who requested to unstake.
    /// @param mETHLocked The amount of mETH that will be burned when the request is claimed.
    /// @param ethRequested The amount of ETH that will be returned to the requester.
    /// @param cumulativeETHRequested The cumulative amount of ETH requested at the time of the unstake request.
    /// @param blockNumber The block number at the point at which the request was created.
    event UnstakeRequestCreated(
        uint256 indexed id,
        address indexed requester,
        uint256 mETHLocked,
        uint256 ethRequested,
        uint256 cumulativeETHRequested,
        uint256 blockNumber
    );

    /// @notice Claimed emitted when an unstake request has been claimed.
    /// @param id The id of the unstake request.
    /// @param requester The address of the user who requested to unstake.
    /// @param mETHLocked The amount of mETH that will be burned when the request is claimed.
    /// @param ethRequested The amount of ETH that will be returned to the requester.
    /// @param cumulativeETHRequested The cumulative amount of ETH requested at the time of the unstake request.
    /// @param blockNumber The block number at the point at which the request was created.
    event UnstakeRequestClaimed(
        uint256 indexed id,
        address indexed requester,
        uint256 mETHLocked,
        uint256 ethRequested,
        uint256 cumulativeETHRequested,
        uint256 blockNumber
    );

    /// @notice Cancelled emitted when an unstake request has been cancelled by an admin.
    /// @param id The id of the unstake request.
    /// @param requester The address of the user who requested to unstake.
    /// @param mETHLocked The amount of mETH that will be burned when the request is claimed.
    /// @param ethRequested The amount of ETH that will be returned to the requester.
    /// @param cumulativeETHRequested The cumulative amount of ETH requested at the time of the unstake request.
    /// @param blockNumber The block number at the point at which the request was created.
    event UnstakeRequestCancelled(
        uint256 indexed id,
        address indexed requester,
        uint256 mETHLocked,
        uint256 ethRequested,
        uint256 cumulativeETHRequested,
        uint256 blockNumber
    );
}

// 管理用户解质押请求的核心合约，采用先进先出（FIFO）队列机制处理解质押请求。它负责跟踪请求状态、管理资金分配、确定请求可认领的时机。
contract UnstakeRequestsManager is
    Initializable,
    AccessControlEnumerableUpgradeable,
    IUnstakeRequestsManager,
    UnstakeRequestsManagerEvents,
    ProtocolEvents
{
    // Errors.
    error AlreadyClaimed();
    error DoesNotReceiveETH();
    error NotEnoughFunds(uint256 cumulativeETHOnRequest, uint256 allocatedETHForClaims);
    error NotFinalized();
    error NotRequester();
    error NotStakingContract();

    // 角色权限
    bytes32 public constant MANAGER_ROLE = keccak256("MANAGER_ROLE");  // 管理员角色
    bytes32 public constant REQUEST_CANCELLER_ROLE = keccak256("REQUEST_CANCELLER_ROLE");     // 请求取消角色

    // 核心合约引用
    IStakingReturnsWrite public stakingContract;   // 质押合约引用
    IOracleReadRecord public oracle;  // 语言机合约引用
    IMETH public mETH;   // mETH代币合约引用

    // 资金跟踪状态变量
    uint256 public allocatedETHForClaims;  // 已分配用于认领的ETH总量（从质押合约转入）
    uint256 public totalClaimed;  // 已认领的 ETH 总量
    uint128 public latestCumulativeETHRequested;  // 最新的累积ETH请求量

    //请求确认机制
    uint256 public numberOfBlocksToFinalize;   // 请求确认所需的区块数

    // 请求队列（内部存储）
    UnstakeRequest[] internal _unstakeRequests;  // 用于解质押请求数组（先进先出队列）

    /// @notice Configuration for contract initialization.
    struct Init {
        address admin;
        address manager;
        address requestCanceller;
        IMETH mETH;
        IStakingReturnsWrite stakingContract;
        IOracleReadRecord oracle;
        uint256 numberOfBlocksToFinalize;
    }

    constructor() {
        _disableInitializers();
    }

    /// @notice Inititalizes the contract.
    /// @dev MUST be called during the contract upgrade to set up the proxies state.
    function initialize(Init memory init) external initializer {
        __AccessControlEnumerable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, init.admin);
        numberOfBlocksToFinalize = init.numberOfBlocksToFinalize;
        stakingContract = init.stakingContract;
        oracle = init.oracle;
        mETH = init.mETH;

        _grantRole(MANAGER_ROLE, init.manager);
        _grantRole(REQUEST_CANCELLER_ROLE, init.requestCanceller);
    }

    /*
     * 创建新的解质押请求（只能由质押合约调用）
     * @param requester 请求者地址
     * @param mETHLocked 锁定的mETH数量
     * @param ethRequested 请求的ETH数量
     * @return 请求ID
     *
     * 执行逻辑：
     * 1. 计算新的累积ETH请求量
     * 2. 创建请求对象并添加到队列
     * 3. 更新状态变量并发出事件
     */
    function create(address requester, uint128 mETHLocked, uint128 ethRequested) external onlyStakingContract returns (uint256){
        // 计算新的累积请求量 = 之前的累积量 + 当前请求量
        // cumulativeETHRequested的作用：
        // 1. 确定请求在队列中的位置
        // 2. 判断是否有足够资金可以认领
        // 3. 实现FIFO处理逻辑
        uint128 currentCumulativeETHRequested = latestCumulativeETHRequested + ethRequested;

        // 请求ID就是数组的当前长度（从0开始）
        uint256 requestID = _unstakeRequests.length;

        // 创建请求对象
        UnstakeRequest memory unstakeRequest = UnstakeRequest({
            id: uint128(requestID),          // 请求 ID -在数组中的索引
            requester: requester,            // 请求者地址
            mETHLocked: mETHLocked,          // 锁定的 mETH 数量-将在认领时销毁
            ethRequested: ethRequested,      // 请求的 ETH 数量
            cumulativeETHRequested: currentCumulativeETHRequested,  // 创建该请求时的累积ETH请求量（关键！）
            blockNumber: uint64(block.number)          // 请求创建时的区块号
        });

        // 添加到队列并更新状态
        _unstakeRequests.push(unstakeRequest);

        latestCumulativeETHRequested = currentCumulativeETHRequested;

        emit UnstakeRequestCreated(
            requestID, requester, mETHLocked, ethRequested, currentCumulativeETHRequested, block.number
        );
        return requestID;
    }

    /**
     * 认领解质押请求（只能由质押合约调用）
     * @param requestID 请求ID
     * @param requester 请求者地址
     *
     * 认领条件（全部满足才能认领）：
     * 1. 请求存在且未被认领
     * 2. 调用者是请求的创建者
     * 3. 请求已经确认（过了确认期）
     * 4. 有足够的资金可以支付
     */
    function claim(uint256 requestID, address requester) external onlyStakingContract {
        UnstakeRequest memory request = _unstakeRequests[requestID];

        // 检查1：请求是否存在（已认领的请求会被删除，requester变为0）
        if (request.requester == address(0)) {
            revert AlreadyClaimed();
        }

        // 检查2：权限验证
        if (requester != request.requester) {
            revert NotRequester();
        }

        // 检查3：确认性验证（基于区块数和Oracle状态）
        if (!_isFinalized(request)) {
            revert NotFinalized();
        }

        // 检查4：资金充足性验证
        // 核心逻辑：请求的累积量 <= 已分配的资金量
        if (request.cumulativeETHRequested > allocatedETHForClaims) {
            revert NotEnoughFunds(request.cumulativeETHRequested, allocatedETHForClaims);
        }

        // 执行认领
        delete _unstakeRequests[requestID];       // 删除请求（防止重复认领）
        totalClaimed += request.ethRequested;     // 更新已认领总额

        emit UnstakeRequestClaimed({
            id: requestID,
            requester: requester,
            mETHLocked: request.mETHLocked,
            ethRequested: request.ethRequested,
            cumulativeETHRequested: request.cumulativeETHRequested,
            blockNumber: request.blockNumber
        });

        // 关键：在这里销毁锁定的mETH代币（而不是在请求创建时）
        // 这样设计的原因：只有成功认领才真正销毁代币，失败的请求可以退还
        mETH.burn(request.mETHLocked);

        // 转移 ETH 给用户
        Address.sendValue(payable(requester), request.ethRequested);
    }

    /**
     * 紧急情况下取消未确认的请求
     * @param maxCancel 最多取消的请求数量
     * @return hasMore 是否还有更多未确认请求需要取消
     *
     * 使用场景：
     * 1. 协议遇到紧急情况需要暂停
     * 2. Oracle数据异常导致确认机制失效
     * 3. 需要回收资金进行协议治理
     */
    function cancelUnfinalizedRequests(uint256 maxCancel) external onlyRole(REQUEST_CANCELLER_ROLE) returns (bool) {
        uint256 length = _unstakeRequests.length;
        if (length == 0) {
            return false;
        }

        if (length < maxCancel) {
            maxCancel = length;
        }

        // 缓存被取消的请求，遵循检查-效果-交互模式
        UnstakeRequest[] memory requests = new UnstakeRequest[](maxCancel);

        uint256 numCancelled = 0;
        uint128 amountETHCancelled = 0;

        // 从队列末尾开始取消（最新的请求）
        while (numCancelled < maxCancel) {
            UnstakeRequest memory request = _unstakeRequests[_unstakeRequests.length - 1];

            // 如果遇到已确认的请求，停止取消
            if (_isFinalized(request)) {
                break;
            }

            // 从队列中移除并记录
            _unstakeRequests.pop();
            requests[numCancelled] = request;
            ++numCancelled;
            amountETHCancelled += request.ethRequested;

            emit UnstakeRequestCancelled(
                request.id,
                request.requester,
                request.mETHLocked,
                request.ethRequested,
                request.cumulativeETHRequested,
                request.blockNumber
            );
        }

        // 调整累积请求量状态
        if (amountETHCancelled > 0) {
            latestCumulativeETHRequested -= amountETHCancelled;
        }

        // 检查是否还有更多未确认请求
        bool hasMore;
        uint256 remainingRequestsLength = _unstakeRequests.length;
        if (remainingRequestsLength == 0) {
            hasMore = false;
        } else {
            UnstakeRequest memory latestRemainingRequest = _unstakeRequests[remainingRequestsLength - 1];
            hasMore = !_isFinalized(latestRemainingRequest);
        }

        // 退还被取消请求的 mETH （没有销毁，而是退还）
        for (uint256 i = 0; i < numCancelled; i++) {
            SafeERC20Upgradeable.safeTransfer(mETH, requests[i].requester, requests[i].mETHLocked);
        }

        return hasMore;
    }

    /**
     * 接收来自质押合约的ETH分配
     * 这是FIFO队列得以工作的资金来源
     *
     * 工作原理：
     * 1. 质押合约调用allocateETH()发送ETH
     * 2. 增加allocatedETHForClaims余额
     * 3. 使更多排队的请求变为可认领状态
     */
    function allocateETH() external payable onlyStakingContract {
        allocatedETHForClaims += msg.value;
        // 例子：假设当前队列状态
        // 请求A：累积量100 ETH
        // 请求B：累积量200 ETH
        // 请求C：累积量350 ETH
        //
        // 如果 allocatedETHForClaims = 250 ETH：
        // - 请求A可认领（100 <= 250）
        // - 请求B可认领（200 <= 250）
        // - 请求C不可认领（350 > 250）
    }

    /// @inheritdoc IUnstakeRequestsManagerWrite
    /// @dev Helps during the emergency scenario where we cancel unstake requests and we want to move ether back into
    /// the staking contract.
    function withdrawAllocatedETHSurplus() external onlyStakingContract {
        uint256 toSend = allocatedETHSurplus();
        if (toSend == 0) {
            return;
        }
        allocatedETHForClaims -= toSend;
        stakingContract.receiveFromUnstakeRequestsManager{value: toSend}();
    }

    /// @notice Returns the ID of the next unstake requests to be created.
    function nextRequestId() external view returns (uint256) {
        return _unstakeRequests.length;
    }

    /// @inheritdoc IUnstakeRequestsManagerRead
    function requestByID(uint256 requestID) external view returns (UnstakeRequest memory) {
        return _unstakeRequests[requestID];
    }

    /**
     * 查询请求的状态信息
     * @param requestID 请求ID
     * @return isFinalized 是否已确认
     * @return claimableAmount 当前可认领的金额（可能部分认领）
     *
     * 这个函数很有用，用户可以：
     * 1. 检查请求是否可以认领
     * 2. 了解资金到位情况
     * 3. 估算认领时间
     */
    function requestInfo(uint256 requestID) external view returns (bool, uint256) {
        UnstakeRequest memory request = _unstakeRequests[requestID];

        bool isFinalized = _isFinalized(request);
        uint256 claimableAmount = 0;

        // 计算可认领金额的巧妙逻辑：
        // 1. 请求前面需要的资金 = 请求累积量 - 请求自身金额
        uint256 allocatedEthRequired = request.cumulativeETHRequested - request.ethRequested;

        // 2. 如果已分配资金 > 前面需要的资金，说明轮到这个请求了
        if (allocatedEthRequired < allocatedETHForClaims) {
            // 3. 可认领金额 = min(超出部分, 请求金额)
            // 这处理了部分资金到位的情况
            claimableAmount = Math.min(allocatedETHForClaims - allocatedEthRequired, request.ethRequested);
        }
        return (isFinalized, claimableAmount);
    }

    /// @inheritdoc IUnstakeRequestsManagerRead
    /// @dev Compares the latest the allocatedETHForClaims value and the cumulative ETH requested value to determine if
    /// there's a surplus.
    function allocatedETHSurplus() public view returns (uint256) {
        if (allocatedETHForClaims > latestCumulativeETHRequested) {
            return allocatedETHForClaims - latestCumulativeETHRequested;
        }
        return 0;
    }

    /// @inheritdoc IUnstakeRequestsManagerRead
    /// @dev Compares the latest cumulative ETH requested value and the allocatedETHForClaims value to determine if
    /// there's a deficit.
    function allocatedETHDeficit() external view returns (uint256) {
        if (latestCumulativeETHRequested > allocatedETHForClaims) {
            return latestCumulativeETHRequested - allocatedETHForClaims;
        }
        return 0;
    }

    /// @inheritdoc IUnstakeRequestsManagerRead
    /// @dev The difference between allocatedETHForClaims and totalClaimed represents the amount of ether waiting to be
    /// claimed.
    function balance() external view returns (uint256) {
        if (allocatedETHForClaims > totalClaimed) {
            return allocatedETHForClaims - totalClaimed;
        }
        return 0;
    }

    /// @notice Updates the number of blocks required to finalize requests.
    /// @param numberOfBlocksToFinalize_ The number of blocks required to finalize requests.
    function setNumberOfBlocksToFinalize(uint256 numberOfBlocksToFinalize_) external onlyRole(MANAGER_ROLE) {
        numberOfBlocksToFinalize = numberOfBlocksToFinalize_;
        emit ProtocolConfigChanged(
            this.setNumberOfBlocksToFinalize.selector,
            "setNumberOfBlocksToFinalize(uint256)",
            abi.encode(numberOfBlocksToFinalize_)
        );
    }

    /**
     * 检查请求是否已确认（可以认领）
     * @param request 请求对象
     * @return 是否已确认
     *
     * 确认条件（双重安全机制）：
     * 1. 请求创建区块 + 确认区块数 <= Oracle最新记录的结束区块
     * 2. 确保Oracle已经处理了请求创建之后的状态
     */
    function _isFinalized(UnstakeRequest memory request) internal view returns (bool) {
        // 计算请求应该确认的区块号
        uint256 finalizeAtBlock = request.blockNumber + numberOfBlocksToFinalize;

        // Oracle的最新记录结束区块
        uint256 oracleEndBlock = oracle.latestRecord().updateEndBlock;

        // 只有Oracle处理到确认区块之后，请求才能被认领
        // 这确保了协议有最新的状态信息来处理请求
        return finalizeAtBlock <= oracleEndBlock;
    }

    /// @dev Validates that the caller is the staking contract.
    modifier onlyStakingContract() {
        if (msg.sender != address(stakingContract)) {
            revert NotStakingContract();
        }
        _;
    }

    // Fallbacks.
    receive() external payable {
        revert DoesNotReceiveETH();
    }

    fallback() external payable {
        revert DoesNotReceiveETH();
    }
}
