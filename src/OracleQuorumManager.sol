// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ProtocolEvents} from "./interfaces/ProtocolEvents.sol";
import {Initializable} from "openzeppelin-upgradeable/proxy/utils/Initializable.sol";
import {AccessControlEnumerableUpgradeable} from
    "openzeppelin-upgradeable/access/AccessControlEnumerableUpgradeable.sol";

import {OracleRecord, IOracle} from "./interfaces/IOracle.sol";

interface OracleQuorumManagerEvents {
    /// @notice Emitted when a record has passed quorum and was submitted to the oracle.
    /// @param block The block the record was finalized on.
    event ReportQuorumReached(uint64 indexed block);

    /// @notice Emitted when a record has been reported by a reporter.
    /// @param block The block the record was recorded on.
    /// @param reporter The reporter that reported the record.
    /// @param recordHash The hash of the record that was reported.
    /// @param record The record that was received.
    event ReportReceived(
        uint64 indexed block, address indexed reporter, bytes32 indexed recordHash, OracleRecord record
    );

    /// @notice Emitted when the oracle failed to receive a record from the oracle quorum manager.
    /// @param reason The reason for the failure, i.e. the caught error.
    event OracleRecordReceivedError(bytes reason);
}

// 是Oracle系统的**共识协调层**，负责管理多个Oracle服务的报告，确保只有在达成共识后才将数据转发给Oracle合约进行最终验证。 `OracleQuorumManager`
contract OracleQuorumManager is
    Initializable,
    AccessControlEnumerableUpgradeable,
    OracleQuorumManagerEvents,
    ProtocolEvents
{
    error InvalidReporter();
    error AlreadyReporter();
    error RelativeThresholdExceedsOne();

    /*
     * 三层权限控制
     * 被设置为 的admin `REPORTER_MODIFIER_ROLE``SERVICE_ORACLE_REPORTER`
     * 这意味着只有具备高级权限的账户才能添加/移除Oracle服务
     * 防止恶意Oracle服务自我授权或相互授权
     */
    bytes32 public constant QUORUM_MANAGER_ROLE = keccak256("QUORUM_MANAGER_ROLE"); // 参数管理
    bytes32 public constant REPORTER_MODIFIER_ROLE = keccak256("REPORTER_MODIFIER_ROLE"); // Oracle服务管理
    bytes32 public constant SERVICE_ORACLE_REPORTER = keccak256("SERVICE_ORACLE_REPORTER"); // 报告提交

    /// @dev A basis point (often denoted as bp, 1bp = 0.01%) is a unit of measure used in finance to describe
    /// the percentage change in a financial instrument. This is a constant value set as 10000 which represents
    /// 100% in basis point terms.
    uint16 internal constant _BASIS_POINTS_DENOMINATOR = 10000;

    /// @notice Oracle to finalize reports for.
    IOracle public oracle;

    // 双层映射：区块号 -> 报告者 -> 报告哈希
    mapping(uint64 block => mapping(address reporter => bytes32 recordHash)) public reporterRecordHashesByBlock;
    // 双层映射：区块号 -> 报告哈希 -> 投票计数
    mapping(uint64 block => mapping(bytes32 recordHash => uint256)) public recordHashCountByBlock;

    /// @notice The target number of blocks in a report window.
    uint64 public targetReportWindowBlocks;

    /// @notice The absolute number of reporters that have to submit the same report for it to be accepted.
    uint16 public absoluteThreshold;

    /// @notice The relative number of reporters (in basis points) that have to submit the same report for it to be
    /// accepted. It is a value between 0 and 10000 basis points (i.e., 0 to 100%). It's used to determine what
    /// proportion of the total number of reporters need to agree on a report for it to be accepted.
    /// @dev Scaled with `getRoleMemberCount(SERVICE_ORACLE_REPORTER)`.
    uint16 public relativeThresholdBasisPoints;

    /// @notice Configuration for contract initialization.
    struct Init {
        address admin;
        address reporterModifier;
        address manager;
        address[] allowedReporters;
        IOracle oracle;
    }

    constructor() {
        _disableInitializers();
    }

    /// @notice Inititalizes the contract.
    /// @dev MUST be called during the contract upgrade to set up the proxies state.
    function initialize(Init memory init) external initializer {
        __AccessControlEnumerable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, init.admin);
        _grantRole(REPORTER_MODIFIER_ROLE, init.reporterModifier);
        _setRoleAdmin(SERVICE_ORACLE_REPORTER, REPORTER_MODIFIER_ROLE);

        _grantRole(QUORUM_MANAGER_ROLE, init.manager);

        oracle = init.oracle;
        uint256 len = init.allowedReporters.length;
        for (uint256 i = 0; i < len; i++) {
            _grantRole(SERVICE_ORACLE_REPORTER, init.allowedReporters[i]);
        }

        // Assumes that a block is created every 12 seconds.
        // Might be slightly longer than the 8 hours target in practice as slots can be empty.
        targetReportWindowBlocks = 8 hours / 12 seconds;

        absoluteThreshold = 1;
        relativeThresholdBasisPoints = 0;
    }

    // 双重阈值系统
    function _hasReachedQuroum(uint64 blockNumber, bytes32 recordHash) internal view returns (bool) {
        uint256 numReports = recordHashCountByBlock[blockNumber][recordHash];
        uint256 numReporters = getRoleMemberCount(SERVICE_ORACLE_REPORTER);

        return (numReports >= absoluteThreshold)  // 绝对阈值：至少N个同意
            && (numReports * _BASIS_POINTS_DENOMINATOR >= numReporters * relativeThresholdBasisPoints);  // // 相对阈值：至少X%同意
    }

    //防重放攻击，- 确保同一区块的报告只被Oracle处理一次，- 考虑了pending状态，避免竞态条件
    function _wasReceivedByOracle(uint256 updateEndBlock) internal view returns (bool) {
        return oracle.latestRecord().updateEndBlock >= updateEndBlock
            || (oracle.hasPendingUpdate() && oracle.pendingUpdate().updateEndBlock >= updateEndBlock);
    }

    /// @notice Returns the record hash for a given block and reporter.
    /// @param blockNumber The block number.
    /// @param sender The reporter.
    function recordHashByBlockAndSender(uint64 blockNumber, address sender) external view returns (bytes32) {
        return reporterRecordHashesByBlock[blockNumber][sender];
    }

    // 智能报告追踪
    function _trackReceivedRecord(address reporter, OracleRecord calldata record) internal returns (bytes32) {
        bytes32 newHash = keccak256(abi.encode(record));
        emit ReportReceived(record.updateEndBlock, reporter, newHash, record);

        bytes32 previousHash = reporterRecordHashesByBlock[record.updateEndBlock][reporter];
        if (newHash == previousHash) {
            return newHash;  // 重复提交，直接返回
        }

        if (previousHash != 0) {
            // Oracle修改了报告，需要更新计数
            recordHashCountByBlock[record.updateEndBlock][previousHash] -= 1;
        }

        // 记录新的报告
        recordHashCountByBlock[record.updateEndBlock][newHash] += 1;
        reporterRecordHashesByBlock[record.updateEndBlock][reporter] = newHash;

        return newHash;
    }

    // 报告接收与处理
    function receiveRecord(OracleRecord calldata record) external onlyRole(SERVICE_ORACLE_REPORTER) {
        //  第一步：记录和追踪报告
        bytes32 recordHash = _trackReceivedRecord(msg.sender, record);


        // 第二步：检查是否达成共识
        if (!_hasReachedQuroum(record.updateEndBlock, recordHash)) {
            return;  // 未达成共识，等待更多报告
        }

        // 第三步：避免重复提交
        if (_wasReceivedByOracle(record.updateEndBlock)) {
            return;  // Oracle已处理此区块的报告
        }

        emit ReportQuorumReached(record.updateEndBlock);

        // 第四步：转发给Oracle合约
        try oracle.receiveRecord(record) {}
        catch (bytes memory reason) {
            emit OracleRecordReceivedError(reason); //  记录错误但不中断
        }
    }

    /// @notice Sets the target report window size in the number of blocks.
    /// @param newTargetReportWindowBlocks The new target report window size in blocks.
    /// NOTE: Setting this lower than the minimum report size as defined by the oracle is technically valid,
    /// but will result in a failing sanity check.
    function setTargetReportWindowBlocks(uint64 newTargetReportWindowBlocks) external onlyRole(QUORUM_MANAGER_ROLE) {
        targetReportWindowBlocks = newTargetReportWindowBlocks;
        emit ProtocolConfigChanged(
            this.setTargetReportWindowBlocks.selector,
            "setTargetReportWindowBlocks(uint64)",
            abi.encode(newTargetReportWindowBlocks)
        );
    }

    // 灵活的阈值配置
    function setQuorumThresholds(uint16 absoluteThreshold_, uint16 relativeThresholdBasisPoints_)
        external
        onlyRole(QUORUM_MANAGER_ROLE)
    {
        if (relativeThresholdBasisPoints_ > _BASIS_POINTS_DENOMINATOR) {
            revert RelativeThresholdExceedsOne();  // 相对阈值不能超过100%
        }

        emit ProtocolConfigChanged(
            this.setQuorumThresholds.selector,
            "setQuorumThresholds(uint16,uint16)",
            abi.encode(absoluteThreshold_, relativeThresholdBasisPoints_)
        );
        absoluteThreshold = absoluteThreshold_;
        relativeThresholdBasisPoints = relativeThresholdBasisPoints_;
    }
}
