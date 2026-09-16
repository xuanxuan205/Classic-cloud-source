import { createApp } from 'vue'
import { createPinia } from 'pinia'
import router from './router'
import App from './App.vue'
import './style.css'
import { warmUpCrawlerChallenge, warmUpFingerprintSignature } from './utils/axios'
import { getDeviceFingerprint } from './utils/deviceFingerprint'

const app = createApp(App)

app.use(createPinia())
app.use(router)

// IronWall v1.20: 页面加载即静默完成铁壁爬虫挑战握手（真实用户无感）
warmUpCrawlerChallenge()
// IronWall v1.28.16: 预计算设备指纹并镜像 Cookie（攻击封禁时同步锁定设备身份）
void getDeviceFingerprint()
// IronWall v1.29.0: 预建立指纹绑定签名（正式请求携带签名后才信任指纹，防伪造/随机化）
void warmUpFingerprintSignature()

app.mount('#app')
