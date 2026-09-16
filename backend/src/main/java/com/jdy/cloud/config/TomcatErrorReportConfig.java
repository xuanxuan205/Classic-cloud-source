package com.jdy.cloud.config;

import com.jdy.cloud.security.MinimalErrorReportValve;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * IronWall v1.28.9: 挂载最小错误页 Valve，隐藏 Tomcat 技术栈指纹。
 */
@Configuration
public class TomcatErrorReportConfig {

    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> tomcatErrorReportCustomizer() {
        return factory -> {
            MinimalErrorReportValve valve = new MinimalErrorReportValve();
            valve.setShowReport(false);
            valve.setShowServerInfo(false);
            factory.addEngineValves(valve);
        };
    }
}
