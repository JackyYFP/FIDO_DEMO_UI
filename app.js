// FIDO2 WebAuthn 應用程式

// 顯示訊息
function showMessage(text, type) {
    const messageDiv = document.getElementById('message');
    messageDiv.textContent = text;
    messageDiv.className = 'message ' + type;
    messageDiv.style.display = 'block';
    
    setTimeout(() => {
        messageDiv.style.display = 'none';
    }, 5000);
}

// 切換頁籤
function showTab(tab) {
    // 隱藏所有內容
    document.querySelectorAll('.content').forEach(content => {
        content.classList.remove('active');
    });
    document.querySelectorAll('.tab button').forEach(button => {
        button.classList.remove('active');
    });
    
    // 顯示選中的內容
    if (tab === 'register') {
        document.getElementById('registerContent').classList.add('active');
        document.getElementById('registerTab').classList.add('active');
    } else {
        document.getElementById('loginContent').classList.add('active');
        document.getElementById('loginTab').classList.add('active');
    }
}

// 將 ArrayBuffer 轉換為 Base64
function bufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

// 將 Base64 轉換為 ArrayBuffer
function base64ToBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// 註冊功能
async function register() {
    const username = document.getElementById('registerUsername').value;
    const displayName = document.getElementById('displayName').value;
    
    if (!username || !displayName) {
        showMessage('請填寫所有欄位', 'error');
        return;
    }
    
    // 檢查瀏覽器是否支援 WebAuthn
    if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.create) {
        showMessage('您的瀏覽器不支援 FIDO2 功能，請使用最新版的 Chrome、Edge、Safari 或 Firefox', 'error');
        return;
    }
    
    // 檢查是否支援跨平台驗證器（用於手機和桌面）
    try {
        const available = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        console.log('Platform authenticator available:', available);
    } catch (e) {
        console.log('Platform authenticator check failed:', e);
    }
    
    try {
        // 生成隨機 challenge
        const challenge = new Uint8Array(32);
        crypto.getRandomValues(challenge);
        
        // 生成用戶 ID
        const userId = new Uint8Array(16);
        crypto.getRandomValues(userId);
        
        // 取得正確的 RP ID（支援 localhost 和 IP 位址）
        let rpId = window.location.hostname;
        // 如果是 IP 位址，不設定 rpId（讓瀏覽器自動處理）
        const isIpAddress = /^(\d{1,3}\.){3}\d{1,3}$/.test(rpId);
        
        // 設定 publicKey 參數（跨平台驗證器：NFC 智慧卡）
        const publicKeyCredentialCreationOptions = {
            challenge: challenge,
            rp: {
                name: "銀行測試系統"
                // 只有在非 IP 位址時才設定 id
                // IP 位址時讓瀏覽器自動處理
            },
            user: {
                id: userId,
                name: username,
                displayName: displayName
            },
            pubKeyCredParams: [
                { alg: -7, type: "public-key" },   // ES256 (常用於手機和智慧卡)
                { alg: -257, type: "public-key" }, // RS256
                { alg: -8, type: "public-key" }    // EdDSA (部分智慧卡支援)
            ],
            authenticatorSelection: {
                // 注意：手機和部分智慧卡可能需要移除 authenticatorAttachment 限制
                // 讓系統自動選擇可用的驗證器
                userVerification: "required",  // 改為 discouraged，避免手機要求額外驗證
                requireResidentKey: false,  // 不要求常駐金鑰
                residentKey: "required"  // 明確指定不需要常駐金鑰
            },
            timeout: 120000,  // 延長到 120 秒，給使用者更多時間插入智慧卡
            attestation: "none"  // 改為 none，提高相容性
        };
        
        // 只有在非 IP 位址時才設定 rpId
        if (!isIpAddress) {
            publicKeyCredentialCreationOptions.rp.id = rpId;
        }
        
        // 呼叫瀏覽器的 WebAuthn API
        const credential = await navigator.credentials.create({
            publicKey: publicKeyCredentialCreationOptions
        });
        
        // 儲存憑證資訊到 localStorage（實際應用應儲存到伺服器）
        const credentialData = {
            id: credential.id,
            rawId: bufferToBase64(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: bufferToBase64(credential.response.clientDataJSON),
                attestationObject: bufferToBase64(credential.response.attestationObject)
            },
            username: username,
            displayName: displayName
        };
        
        // 將憑證儲存到 localStorage
        localStorage.setItem('fido2_credential_' + username, JSON.stringify(credentialData));
        
        showMessage('註冊成功！您現在可以使用此帳號登入', 'success');
        
        // 清空表單
        document.getElementById('registerUsername').value = '';
        document.getElementById('displayName').value = '';
        
    } catch (error) {
        console.error('註冊錯誤:', error);
        if (error.name === 'NotAllowedError') {
            showMessage('註冊已取消或逾時', 'error');
        } else if (error.name === 'InvalidStateError') {
            showMessage('此裝置已註冊過，請直接登入', 'error');
        } else {
            showMessage('註冊失敗: ' + error.message, 'error');
        }
    }
}

// 登入功能
async function login() {
    const username = document.getElementById('loginUsername').value;
    
    if (!username) {
        showMessage('請輸入帳號', 'error');
        return;
    }
    
    // 檢查瀏覽器是否支援 WebAuthn
    if (!window.PublicKeyCredential || !navigator.credentials || !navigator.credentials.get) {
        showMessage('您的瀏覽器不支援 FIDO2 功能，請使用最新版的 Chrome、Edge、Safari 或 Firefox', 'error');
        return;
    }
    
    try {
        // 從 localStorage 取得憑證
        const storedCredential = localStorage.getItem('fido2_credential_' + username);
        if (!storedCredential) {
            showMessage('找不到此帳號，請先註冊', 'error');
            return;
        }
        
        const credentialData = JSON.parse(storedCredential);
        
        // 生成隨機 challenge
        const challenge = new Uint8Array(32);
        crypto.getRandomValues(challenge);
        
        // 取得正確的 RP ID（支援 localhost 和 IP 位址）
        let rpId = window.location.hostname;
        const isIpAddress = /^(\d{1,3}\.){3}\d{1,3}$/.test(rpId);
        
        // 設定 publicKey 參數（跨平台驗證器：NFC 智慧卡）
        const publicKeyCredentialRequestOptions = {
            challenge: challenge,
            allowCredentials: [{
                id: base64ToBuffer(credentialData.rawId),
                type: 'public-key',
                transports: ['nfc', 'usb', 'ble', 'internal']  // 支援所有可能的傳輸方式
            }],
            timeout: 120000,  // 延長到 120 秒，給使用者更多時間插入智慧卡
            userVerification: "discouraged"  // 改為 discouraged，避免手機要求額外驗證
        };
        
        // 只有在非 IP 位址時才設定 rpId
        if (!isIpAddress) {
            publicKeyCredentialRequestOptions.rpId = rpId;
        }
        
        // 呼叫瀏覽器的 WebAuthn API 進行驗證
        const assertion = await navigator.credentials.get({
            publicKey: publicKeyCredentialRequestOptions
        });
        
        showMessage('登入成功！歡迎 ' + credentialData.displayName, 'success');
        
        // 清空表單
        document.getElementById('loginUsername').value = '';
        
    } catch (error) {
        console.error('登入錯誤:', error);
        if (error.name === 'NotAllowedError') {
            showMessage('登入已取消或逾時', 'error');
        } else {
            showMessage('登入失敗: ' + error.message, 'error');
        }
    }
}

// Enter 鍵支援
document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('registerUsername').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') register();
    });
    document.getElementById('displayName').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') register();
    });
    document.getElementById('loginUsername').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') login();
    });
});
