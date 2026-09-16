package com.jdy.cloud.service;

import com.jdy.cloud.model.Share;
import com.jdy.cloud.repository.ShareRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.List;

/**
 * IronWall v1.28.9: 分享密码存量迁移。
 * 历史分享密码为明文存储，启动时将全部旧密码转换为 sha256$ 加盐哈希格式。
 * 幂等：已带前缀的记录跳过；迁移失败只记日志，不阻断启动。
 */
@Slf4j
@Component
@Order(10)
public class SharePasswordMigration implements ApplicationRunner {

    private final ShareRepository shareRepository;
    private final TransactionTemplate transactionTemplate;

    public SharePasswordMigration(ShareRepository shareRepository, PlatformTransactionManager transactionManager) {
        this.shareRepository = shareRepository;
        this.transactionTemplate = new TransactionTemplate(transactionManager);
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            List<Share> shares = shareRepository.findAll();
            int migrated = 0;
            for (Share share : shares) {
                String stored = share.getPassword();
                if (stored == null || stored.isEmpty()
                        || stored.startsWith(PasswordGuardService.SHARE_PW_HASH_PREFIX)) {
                    continue;
                }
                if (share.getShareCode() == null || share.getShareCode().isEmpty()) {
                    continue;
                }
                share.setPassword(PasswordGuardService.hashSharePassword(share.getShareCode(), stored));
                migrated++;
            }
            if (migrated > 0) {
                final int count = migrated;
                transactionTemplate.executeWithoutResult(status -> shareRepository.saveAll(shares));
                log.info("[IronWall] share password migration: {} plaintext entries converted to salted hash", count);
            }
        } catch (Exception e) {
            log.error("[IronWall] share password migration failed: {}", e.getMessage(), e);
        }
    }
}
