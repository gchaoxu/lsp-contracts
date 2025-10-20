// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "openzeppelin-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlEnumerableUpgradeable} from
    "openzeppelin-upgradeable/access/AccessControlEnumerableUpgradeable.sol";
import {Math} from "openzeppelin/utils/math/Math.sol";

import {ProtocolEvents} from "./interfaces/ProtocolEvents.sol";
import {
    IOracle,
    IOracleReadRecord,
    IOracleReadPending,
    IOracleWrite,
    IOracleManager,
    OracleRecord
} from "./interfaces/IOracle.sol";
import {IStakingInitiationRead} from "./interfaces/IStaking.sol";
import {IReturnsAggregatorWrite} from "./interfaces/IReturnsAggregator.sol";
import {IPauser} from "./interfaces/IPauser.sol";

/// @notice Events emitted by the oracle contract.
interface OracleEvents {
    /// @notice Emitted when a new oracle record was added to the list of oracle records. A pending record will only
    /// emit this event if it was accepted by the admin.
    /// @param index The index of the new record.
    /// @param record The new record that was added to the list.
    event OracleRecordAdded(uint256 indexed index, OracleRecord record);

    /// @notice Emitted when a record has been modified.
    /// @param index The index of the record that was modified.
    /// @param record The newly modified record.
    event OracleRecordModified(uint256 indexed index, OracleRecord record);

    /// @notice Emitted when a pending update has been rejected.
    /// @param pendingUpdate The rejected pending update.
    event OraclePendingUpdateRejected(OracleRecord pendingUpdate);

    /// @notice Emitted when the oracle's record did not pass a sanity check.
    /// @param reasonHash The hash of the reason for the record rejection.
    /// @param reason The reason for the record rejection.
    /// @param record The record that was rejected.
    /// @param value The value that violated a bound.
    /// @param bound The bound of the rejected update.
    event OracleRecordFailedSanityCheck(
        bytes32 indexed reasonHash, string reason, OracleRecord record, uint256 value, uint256 bound
    );
}

contract Oracle is Initializable, AccessControlEnumerableUpgradeable, IOracle, OracleEvents, ProtocolEvents {
    // Errors.
    error CannotUpdateWhileUpdatePending();
    error CannotModifyInitialRecord();
    error InvalidConfiguration();
    error InvalidRecordModification();
    error InvalidUpdateStartBlock(uint256 wantUpdateStartBlock, uint256 gotUpdateStartBlock);
    error InvalidUpdateEndBeforeStartBlock(uint256 end, uint256 start);
    error InvalidUpdateMoreDepositsProcessedThanSent(uint256 processed, uint256 sent);
    error InvalidUpdateMoreValidatorsThanInitiated(uint256 numValidatorsOnRecord, uint256 numInitiatedValidators);
    error NoUpdatePending();
    error Paused();
    error RecordDoesNotExist(uint256 idx);
    error UnauthorizedOracleUpdater(address sender, address oracleUpdater);
    error UpdateEndBlockNumberNotFinal(uint256 updateFinalizingBlock);
    error ZeroAddress();

    //角色权限定义
    bytes32 public constant ORACLE_MANAGER_ROLE = keccak256("ORACLE_MANAGER_ROLE");    // Oracle管理员角色
    bytes32 public constant ORACLE_MODIFIER_ROLE = keccak256("ORACLE_MODIFIER_ROLE");  //  Oracle记录修改员角色
    bytes32 public constant ORACLE_PENDING_UPDATE_RESOLVER_ROLE = keccak256("ORACLE_PENDING_UPDATE_RESOLVER_ROLE");  // 待处理更新解决角色

    /// @notice Finalization block number delta upper bound for the setter.
    uint256 internal constant _FINALIZATION_BLOCK_NUMBER_DELTA_UPPER_BOUND = 2048;

    //数据存储
    OracleRecord[] internal _records;    // Oracle记录数组（历史快照）

    // 待处理更新机制
    bool public hasPendingUpdate;           // 是否有待处理的更新
    OracleRecord internal _pendingUpdate;   // 待处理的更新记录（如果合理性检查失败）

    // 确认机制参数
    uint256 public finalizationBlockNumberDelta;  // 确认所需要的区块数差值（默认2个 epoch）
    address public oracleUpdater;  // 允许推送 Oracle 更新的地址

    //核心合约引用
    IPauser public pauser;  // 暂停合约
    IStakingInitiationRead public staking;  // 质押合约
    IReturnsAggregatorWrite public aggregator;  // 收益聚合器合约

    //
    // Sanity check parameters
    //

    /// @notice The minimum deposit per new validator (on average).
    /// @dev This is used to put constraints on the reported processed deposits. Even thought this will foreseeably be
    /// 32 ETH, we keep it as a configurable parameter to allow for future changes.
    uint256 public minDepositPerValidator;

    /// @notice The maximum deposit per new validator (on average).
    /// @dev This is used to put constraints on the reported processed deposits. Even thought this will foreseeably be
    /// 32 ETH, we keep it as a configurable parameter to allow for future changes.
    uint256 public maxDepositPerValidator;

    /// @notice The minimum consensus layer gain per block (in part-per-trillion, i.e. in units of 1e-12).
    /// @dev This is used to put constraints on the reported change of the total consensus layer balance.
    uint40 public minConsensusLayerGainPerBlockPPT;

    /// @notice The maximum consensus layer gain per block (in part-per-trillion, i.e. in units of 1e-12).
    /// @dev This is used to put constraints on the reported change of the total consensus layer balance.
    uint40 public maxConsensusLayerGainPerBlockPPT;

    /// @notice The maximum consensus layer loss (in part-per-million, i.e. in units of 1e-6).
    /// This value doesn't scale with time and represents a total loss over a given period, remaining independent of the
    /// blocks. It encapsulates scenarios such as a single substantial slashing event or concurrent off-chain oracle
    /// service downtime with validators incurring attestation penalties.
    /// @dev This is used to put constraints on the reported change of the total consensus layer balance.
    uint24 public maxConsensusLayerLossPPM;

    /// @notice The minimum report size to allow for any report.
    /// @dev This value helps defend against the extreme bounds of checks in the case of malicious oracles.
    uint16 public minReportSizeBlocks;

    /// @notice The denominator of a parts-per-million (PPM) fraction.
    uint24 internal constant _PPM_DENOMINATOR = 1e6;

    /// @notice The denominator of a parts-per-trillion (PPT) fraction.
    uint40 internal constant _PPT_DENOMINATOR = 1e12;

    /// @notice Configuration for contract initialization.
    struct Init {
        address admin;
        address manager;
        address oracleUpdater;
        address pendingResolver;
        IReturnsAggregatorWrite aggregator;
        IPauser pauser;
        IStakingInitiationRead staking;
    }

    constructor() {
        _disableInitializers();
    }

    /// @notice Inititalizes the contract.
    /// @dev MUST be called during the contract upgrade to set up the proxies state.
    function initialize(Init memory init) external initializer {
        __AccessControlEnumerable_init();

        // We intentionally do not assign an address to the ORACLE_MODIFIER_ROLE. This is to prevent
        // unintentional oracle modifications outside of exceptional circumstances.
        _grantRole(DEFAULT_ADMIN_ROLE, init.admin);
        _grantRole(ORACLE_MANAGER_ROLE, init.manager);
        _grantRole(ORACLE_PENDING_UPDATE_RESOLVER_ROLE, init.pendingResolver);

        aggregator = init.aggregator;
        oracleUpdater = init.oracleUpdater;
        pauser = init.pauser;
        staking = init.staking;

        // Assumes 2 epochs (in blocks).
        finalizationBlockNumberDelta = 64;

        minReportSizeBlocks = 100;
        minDepositPerValidator = 32 ether;
        maxDepositPerValidator = 32 ether;

        // 7200 slots per day * 365 days per year = 2628000 slots per year
        // assuming 5% yield per year
        // 5% / 2628000 = 1.9025e-8
        // 1.9025e-8 per slot = 19025 PPT
        maxConsensusLayerGainPerBlockPPT = 190250; // 10x approximate rate
        minConsensusLayerGainPerBlockPPT = 1903; // 0.1x approximate rate

        // We chose a lower bound of a 0.1% loss for the protocol based on several factors:
        //
        // - Sanity check should not fail for normal operations where we define normal operations as attestation
        // penalties due to offline validators. Supposing all our validators go offline, the protocol is expected
        // to have a 0.03% missed attestation penalty on mainnet for all validators' balance for a single day.
        // - For a major slashing event, (i.e. 1 ETH slashed for half of our validators), we should expect a drop of
        // 1.56% of the entire protocol. This *must* trigger the consensus layer loss lower bound.
        maxConsensusLayerLossPPM = 1000;

        // Initializing the oracle with a zero record, so that all contract functions (e.g. `latestRecord`) work as
        // expected. We set updateEndBlock to be the block at which the staking contract was initialized, so that the
        // first time an Oracle computes a report, it doesn't bother looking at blocks earlier than when the protocol
        // was deployed. That would be a waste, as our system would not have been running then.
        _pushRecord(OracleRecord(0, uint64(staking.initializationBlockNumber()), 0, 0, 0, 0, 0, 0));
    }

    /** 合理性检查参数（重要的安全机制）
     * 接收新的Oracle记录（只能由指定的oracleUpdater调用）
     * @param newRecord 要更新的Oracle记录
     *
     * 执行流程：
     * 1. 权限和暂停状态检查
     * 2. 技术验证（严格的不变性检查）
     * 3. 确认性检查（基于区块高度）
     * 4. 合理性检查（边界和异常检测）
     * 5. 根据检查结果决定接受、拒绝或暂停
     */
    function receiveRecord(OracleRecord calldata newRecord) external {
        // 1. 基础检查
        if (pauser.isSubmitOracleRecordsPaused()) {
            revert Paused();
        }

        if (msg.sender != oracleUpdater) {
            revert UnauthorizedOracleUpdater(msg.sender, oracleUpdater);
        }

        if (hasPendingUpdate) {
            revert CannotUpdateWhileUpdatePending();
        }

        // 2. 技术验证-确保数据逻辑正确
        validateUpdate(_records.length - 1, newRecord);

        // 3. 确认性检查-确保报告期间已最终确认
        uint256 updateFinalizingBlock = newRecord.updateEndBlock + finalizationBlockNumberDelta;
        if (block.number < updateFinalizingBlock) {
            revert UpdateEndBlockNumberNotFinal(updateFinalizingBlock);
        }

        // 4. 合理性检查-检查数据是否在合理范围内
        (string memory rejectionReason, uint256 value, uint256 bound) = sanityCheckUpdate(latestRecord(), newRecord);

        if (bytes(rejectionReason).length > 0) {
            // 合理性检查失败-标记为待处理并暂停协议
            _pendingUpdate = newRecord;
            hasPendingUpdate = true;

            emit OracleRecordFailedSanityCheck({
                reasonHash: keccak256(bytes(rejectionReason)),
                reason: rejectionReason,
                record: newRecord,
                value: value,
                bound: bound
            });
            // 重要：暂停协议等待管理员处理
            pauser.pauseAll();
            return;
        }

        // 5. 检查通过-添加记录并处理收益
        _pushRecord(newRecord);
    }

    /** 紧急记录修复功能
     * 修改现有记录（紧急情况使用）
     * @param idx 要修改的记录索引
     * @param record 新的记录数据
     *
     * 使用场景：
     * 1. Oracle计算错误
     * 2. 恶意Oracle攻击后的数据修正
     * 3. 链下系统故障导致的数据偏差
     *
     * 注意：这个函数会影响汇率，已提交解质押请求的用户不受影响
     */
    function modifyExistingRecord(uint256 idx, OracleRecord calldata record) external onlyRole(ORACLE_MODIFIER_ROLE) {
        // 不能修改初始记录（索引0）
        if (idx == 0) {
            revert CannotModifyInitialRecord();
        }

        if (idx >= _records.length) {
            revert RecordDoesNotExist(idx);
        }

        OracleRecord storage existingRecord = _records[idx];

        // 不能修改记录的时间边界（防止出现时间间隙）
        if ( existingRecord.updateStartBlock != record.updateStartBlock || existingRecord.updateEndBlock != record.updateEndBlock ) {
            revert InvalidRecordModification();
        }

        // 对新记录进行技术验证
        validateUpdate(idx - 1, record);

        // 计算修改后是否需要补充处理收益
        uint256 missingRewards = 0;
        uint256 missingPrincipals = 0;

        // 如果新记录报告了更多的提取奖励/本金，需要补充处理
        if (record.windowWithdrawnRewardAmount > existingRecord.windowWithdrawnRewardAmount) {
            missingRewards = record.windowWithdrawnRewardAmount - existingRecord.windowWithdrawnRewardAmount;
        }
        if (record.windowWithdrawnPrincipalAmount > existingRecord.windowWithdrawnPrincipalAmount) {
            missingPrincipals = record.windowWithdrawnPrincipalAmount - existingRecord.windowWithdrawnPrincipalAmount;
        }

        // 更新记录
        _records[idx] = record;
        emit OracleRecordModified(idx, record);

        // 如果有缺失的收益，触发补充处理（外部调用放在最后避免重入）
        if (missingRewards > 0 || missingPrincipals > 0) {
            aggregator.processReturns({
                rewardAmount: missingRewards,
                principalAmount: missingPrincipals,
                shouldIncludeELRewards: false      // 修改时不包含执行层奖励
            });
        }
    }

    /** 技术验证函数
     * 验证新Oracle记录的技术正确性
     * @param prevRecordIndex 前一条记录的索引
     * @param newRecord 新记录
     *
     * 这是最严格的验证，确保Oracle的不变性：
     * 1. 时间窗口连续性
     * 2. 累积数据单调性
     * 3. 与链上数据一致性
     */
    function validateUpdate(uint256 prevRecordIndex, OracleRecord calldata newRecord) public view {
        OracleRecord storage prevRecord = _records[prevRecordIndex];

        // 验证1：时间窗口有效性
        if (newRecord.updateEndBlock <= newRecord.updateStartBlock) {
            revert InvalidUpdateEndBeforeStartBlock(newRecord.updateEndBlock, newRecord.updateStartBlock);
        }

        // 验证2：时间窗口连续性（新记录必须紧接前一记录）
        if (newRecord.updateStartBlock != prevRecord.updateEndBlock + 1) {
            revert InvalidUpdateStartBlock(prevRecord.updateEndBlock + 1, newRecord.updateStartBlock);
        }

        // 验证3：存款处理一致性，链下Oracle只能跟踪来自协议的存款
        if (newRecord.cumulativeProcessedDepositAmount > staking.totalDepositedInValidators()) {
            revert InvalidUpdateMoreDepositsProcessedThanSent(
                newRecord.cumulativeProcessedDepositAmount, staking.totalDepositedInValidators()
            );
        }

        // 验证4：验证器数量一致性，报告的验证器总数不能超过协议启动的数量
        if ( uint256(newRecord.currentNumValidatorsNotWithdrawable) + uint256(newRecord.cumulativeNumValidatorsWithdrawable) > staking.numInitiatedValidators() ) {
            revert InvalidUpdateMoreValidatorsThanInitiated(
                newRecord.currentNumValidatorsNotWithdrawable + newRecord.cumulativeNumValidatorsWithdrawable,
                staking.numInitiatedValidators()
            );
        }
    }

    /**
     * 对Oracle更新进行合理性检查
     * @param prevRecord 前一条记录
     * @param newRecord 新记录
     * @return (拒绝原因, 异常值, 边界值) - 如果原因为空字符串则通过检查
     *
     * 合理性检查比技术验证更宽松，主要防止：
     * 1. 恶意Oracle攻击
     * 2. 计算错误
     * 3. 异常市场条件
     */
    function sanityCheckUpdate(OracleRecord memory prevRecord, OracleRecord calldata newRecord) public view returns (string memory, uint256, uint256) {
        uint64 reportSize = newRecord.updateEndBlock - newRecord.updateStartBlock + 1;
        {
            // 检查1：报告大小
            if (reportSize < minReportSizeBlocks) {
                return ("Report blocks below minimum bound", reportSize, minReportSizeBlocks);
            }
        }
        {
            // 检查2：验证器数量单调性
            if (newRecord.cumulativeNumValidatorsWithdrawable < prevRecord.cumulativeNumValidatorsWithdrawable) {
                return (
                    "Cumulative number of withdrawable validators decreased",
                    newRecord.cumulativeNumValidatorsWithdrawable,
                    prevRecord.cumulativeNumValidatorsWithdrawable
                );
            }
            {
                uint256 prevNumValidators = prevRecord.currentNumValidatorsNotWithdrawable + prevRecord.cumulativeNumValidatorsWithdrawable;
                uint256 newNumValidators = newRecord.currentNumValidatorsNotWithdrawable + newRecord.cumulativeNumValidatorsWithdrawable;

                if (newNumValidators < prevNumValidators) {
                    return ("Total number of validators decreased", newNumValidators, prevNumValidators);
                }
            }
        }

        {
            // 检查3：存款处理单调性
            if (newRecord.cumulativeProcessedDepositAmount < prevRecord.cumulativeProcessedDepositAmount) {
                return (
                    "Processed deposit amount decreased",
                    newRecord.cumulativeProcessedDepositAmount,
                    prevRecord.cumulativeProcessedDepositAmount
                );
            }

            // 检查4：新存款与验证器比例合理性
            uint256 newDeposits = (newRecord.cumulativeProcessedDepositAmount - prevRecord.cumulativeProcessedDepositAmount);
            uint256 newValidators = (
                newRecord.currentNumValidatorsNotWithdrawable + newRecord.cumulativeNumValidatorsWithdrawable
                    - prevRecord.currentNumValidatorsNotWithdrawable - prevRecord.cumulativeNumValidatorsWithdrawable
            );

            if (newDeposits < newValidators * minDepositPerValidator) {
                return (
                    "New deposits below min deposit per validator", newDeposits, newValidators * minDepositPerValidator
                );
            }

            if (newDeposits > newValidators * maxDepositPerValidator) {
                return (
                    "New deposits above max deposit per validator", newDeposits, newValidators * maxDepositPerValidator
                );
            }
        }

        // 检查5：共识层余额变化合理性（核心检查！）
        return _checkConsensusLayerBalanceChange(prevRecord, newRecord, reportSize);
    }

    /**
     * 检查共识层余额变化是否合理
     * 这是最复杂也是最重要的检查
     */
    function _checkConsensusLayerBalanceChange(
        OracleRecord memory prevRecord,
        OracleRecord calldata newRecord,
        uint64 reportSize
    ) internal view returns (string memory, uint256, uint256) {

        // 计算基准总余额（没有奖励/惩罚情况下的期望余额）
        uint256 baselineGrossCLBalance = prevRecord.currentTotalValidatorBalance +
            (newRecord.cumulativeProcessedDepositAmount - prevRecord.cumulativeProcessedDepositAmount);

        // 计算实际总余额（包含所有提取的资金）
        uint256 newGrossCLBalance = newRecord.currentTotalValidatorBalance +
                        newRecord.windowWithdrawnPrincipalAmount +
                        newRecord.windowWithdrawnRewardAmount;

        // 下边界检查：防止异常损失
        uint256 lowerBound = baselineGrossCLBalance
            - Math.mulDiv(maxConsensusLayerLossPPM, baselineGrossCLBalance, _PPM_DENOMINATOR)  // 最大损失
            + Math.mulDiv(minConsensusLayerGainPerBlockPPT * reportSize, baselineGrossCLBalance, _PPT_DENOMINATOR); // 最小收益

        if (newGrossCLBalance < lowerBound) {
            return ("Consensus layer change below min gain or max loss", newGrossCLBalance, lowerBound);
        }

        // 上边界检查：防止异常收益
        uint256 upperBound = baselineGrossCLBalance +
                            Math.mulDiv(maxConsensusLayerGainPerBlockPPT * reportSize, baselineGrossCLBalance, _PPT_DENOMINATOR);

        if (newGrossCLBalance > upperBound) {
            return ("Consensus layer change above max gain", newGrossCLBalance, upperBound);
        }

        return ("", 0, 0); // 检查通过
    }

    /** 记录处理和待处理更新管理
     * 内部函数：推送记录到数组并触发收益处理
     * @param record 要推送的记录
     */
    function _pushRecord(OracleRecord memory record) internal {
        emit OracleRecordAdded(_records.length, record);
        _records.push(record);

        // 重要：触发收益聚合器处理新的收益
        // shouldIncludeELRewards=true 表示包含执行层奖励
        aggregator.processReturns({
            rewardAmount: record.windowWithdrawnRewardAmount,
            principalAmount: record.windowWithdrawnPrincipalAmount,
            shouldIncludeELRewards: true
        });
    }

    /**
     * 接受待处理的更新（管理员权限）
     * 当合理性检查失败但管理员确认数据正确时使用
     */
    function acceptPendingUpdate() external onlyRole(ORACLE_PENDING_UPDATE_RESOLVER_ROLE) {
        if (!hasPendingUpdate) {
            revert NoUpdatePending();
        }

        _pushRecord(_pendingUpdate);
        _resetPending();
    }

    /**
     * 拒绝待处理的更新（管理员权限）
     * 当管理员确认数据有问题时使用
     */
    function rejectPendingUpdate() external onlyRole(ORACLE_PENDING_UPDATE_RESOLVER_ROLE) {
        if (!hasPendingUpdate) {
            revert NoUpdatePending();
        }

        emit OraclePendingUpdateRejected(_pendingUpdate);
        _resetPending();
    }

    //重置待处理状态
    function _resetPending() internal {
        delete _pendingUpdate;
        hasPendingUpdate = false;
    }

    /// @inheritdoc IOracleReadRecord
    function latestRecord() public view returns (OracleRecord memory) {
        return _records[_records.length - 1];
    }

    /// @inheritdoc IOracleReadPending
    function pendingUpdate() external view returns (OracleRecord memory) {
        if (!hasPendingUpdate) {
            revert NoUpdatePending();
        }
        return _pendingUpdate;
    }

    /// @inheritdoc IOracleReadRecord
    function recordAt(uint256 idx) external view returns (OracleRecord memory) {
        return _records[idx];
    }

    /// @inheritdoc IOracleReadRecord
    function numRecords() external view returns (uint256) {
        return _records.length;
    }

    /// @notice Sets the finalization block number delta in the contract.
    /// See also {finalizationBlockNumberDelta}.
    /// @param finalizationBlockNumberDelta_ The new finalization block number delta.
    function setFinalizationBlockNumberDelta(uint256 finalizationBlockNumberDelta_)
        external
        onlyRole(ORACLE_MANAGER_ROLE)
    {
        if (
            finalizationBlockNumberDelta_ == 0
                || finalizationBlockNumberDelta_ > _FINALIZATION_BLOCK_NUMBER_DELTA_UPPER_BOUND
        ) {
            revert InvalidConfiguration();
        }

        finalizationBlockNumberDelta = finalizationBlockNumberDelta_;
        emit ProtocolConfigChanged(
            this.setFinalizationBlockNumberDelta.selector,
            "setFinalizationBlockNumberDelta(uint256)",
            abi.encode(finalizationBlockNumberDelta_)
        );
    }

    /// @inheritdoc IOracleManager
    /// @dev See also {oracleUpdater}.
    function setOracleUpdater(address newUpdater) external onlyRole(ORACLE_MANAGER_ROLE) notZeroAddress(newUpdater) {
        oracleUpdater = newUpdater;
        emit ProtocolConfigChanged(this.setOracleUpdater.selector, "setOracleUpdater(address)", abi.encode(newUpdater));
    }

    /// @notice Sets min deposit per validator in the contract.
    /// See also {minDepositPerValidator}.
    /// @param minDepositPerValidator_ The new min deposit per validator.
    function setMinDepositPerValidator(uint256 minDepositPerValidator_) external onlyRole(ORACLE_MANAGER_ROLE) {
        minDepositPerValidator = minDepositPerValidator_;
        emit ProtocolConfigChanged(
            this.setMinDepositPerValidator.selector,
            "setMinDepositPerValidator(uint256)",
            abi.encode(minDepositPerValidator_)
        );
    }

    /// @notice Sets max deposit per validator in the contract.
    /// See also {maxDepositPerValidator}.
    /// @param maxDepositPerValidator_ The new max deposit per validator.
    function setMaxDepositPerValidator(uint256 maxDepositPerValidator_) external onlyRole(ORACLE_MANAGER_ROLE) {
        maxDepositPerValidator = maxDepositPerValidator_;
        emit ProtocolConfigChanged(
            this.setMaxDepositPerValidator.selector,
            "setMaxDepositPerValidator(uint256)",
            abi.encode(maxDepositPerValidator)
        );
    }

    /// @notice Sets min consensus layer gain per block in the contract.
    /// See also {minConsensusLayerGainPerBlockPPT}.
    /// @param minConsensusLayerGainPerBlockPPT_ The new min consensus layer gain per block in parts per trillion.
    function setMinConsensusLayerGainPerBlockPPT(uint40 minConsensusLayerGainPerBlockPPT_)
        external
        onlyRole(ORACLE_MANAGER_ROLE)
        onlyFractionLeqOne(minConsensusLayerGainPerBlockPPT_, _PPT_DENOMINATOR)
    {
        minConsensusLayerGainPerBlockPPT = minConsensusLayerGainPerBlockPPT_;
        emit ProtocolConfigChanged(
            this.setMinConsensusLayerGainPerBlockPPT.selector,
            "setMinConsensusLayerGainPerBlockPPT(uint40)",
            abi.encode(minConsensusLayerGainPerBlockPPT_)
        );
    }

    /// @notice Sets max consensus layer gain per block in the contract.
    /// See also {maxConsensusLayerGainPerBlockPPT}.
    /// @param maxConsensusLayerGainPerBlockPPT_ The new max consensus layer gain per block in parts per million.
    function setMaxConsensusLayerGainPerBlockPPT(uint40 maxConsensusLayerGainPerBlockPPT_)
        external
        onlyRole(ORACLE_MANAGER_ROLE)
        onlyFractionLeqOne(maxConsensusLayerGainPerBlockPPT_, _PPT_DENOMINATOR)
    {
        maxConsensusLayerGainPerBlockPPT = maxConsensusLayerGainPerBlockPPT_;
        emit ProtocolConfigChanged(
            this.setMaxConsensusLayerGainPerBlockPPT.selector,
            "setMaxConsensusLayerGainPerBlockPPT(uint40)",
            abi.encode(maxConsensusLayerGainPerBlockPPT_)
        );
    }

    /// @notice Sets max consensus layer loss per block in the contract.
    /// See also {maxConsensusLayerLossPPM}.
    /// @param maxConsensusLayerLossPPM_ The new max consensus layer loss per block in parts per million.
    function setMaxConsensusLayerLossPPM(uint24 maxConsensusLayerLossPPM_)
        external
        onlyRole(ORACLE_MANAGER_ROLE)
        onlyFractionLeqOne(maxConsensusLayerLossPPM_, _PPM_DENOMINATOR)
    {
        maxConsensusLayerLossPPM = maxConsensusLayerLossPPM_;
        emit ProtocolConfigChanged(
            this.setMaxConsensusLayerLossPPM.selector,
            "setMaxConsensusLayerLossPPM(uint24)",
            abi.encode(maxConsensusLayerLossPPM_)
        );
    }

    /// @notice Sets the minimum report size.
    /// See also {minReportSizeBlocks}.
    /// @param minReportSizeBlocks_ The new minimum report size, in blocks.
    function setMinReportSizeBlocks(uint16 minReportSizeBlocks_) external onlyRole(ORACLE_MANAGER_ROLE) {
        // Sanity check on upper bound is covered by uint16 which is ~9 days.
        minReportSizeBlocks = minReportSizeBlocks_;
        emit ProtocolConfigChanged(
            this.setMinReportSizeBlocks.selector, "setMinReportSizeBlocks(uint16)", abi.encode(minReportSizeBlocks_)
        );
    }

    /// @notice Ensures that the given fraction is less than or equal to one.
    /// @param numerator The numerator of the fraction.
    /// @param denominator The denominator of the fraction.
    modifier onlyFractionLeqOne(uint256 numerator, uint256 denominator) {
        if (numerator > denominator) {
            revert InvalidConfiguration();
        }
        _;
    }

    /// @notice Ensures that the given address is not the zero address.
    /// @param addr The address to check.
    modifier notZeroAddress(address addr) {
        if (addr == address(0)) {
            revert ZeroAddress();
        }
        _;
    }
}
