// 画像読み込み
function loadImage(fileInput, canvasId) {
    return new Promise((resolve, reject) => {
        const file = fileInput.files[0];
        if (!file) return reject("ファイルが選択されていません");

        const reader = new FileReader();
        reader.onload = (e) => {
            const img = new Image();
            img.onload = () => {
                const canvas = document.getElementById(canvasId);
                const ctx = canvas.getContext('2d');
                canvas.width = img.width;
                canvas.height = img.height;
                ctx.drawImage(img, 0, 0);
                resolve(ctx);
            };
            img.src = e.target.result;
        };
        reader.readAsDataURL(file);
    });
}

// パスワード→暗号化キー (PBKDF2)
async function deriveKey(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

// 暗号化処理
async function encryptData(text, password) {
    const enc = new TextEncoder();
    const encodedText = enc.encode(text);

    // ソルトとIVをランダム生成
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // キー生成と暗号化
    const key = await deriveKey(password, salt);
    const encryptedContent = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encodedText
    );

    // Salt + IV + 暗号文
    const encryptedBytes = new Uint8Array(encryptedContent);
    const result = new Uint8Array(salt.length + iv.length + encryptedBytes.length);
    result.set(salt, 0);
    result.set(iv, 16);
    result.set(encryptedBytes, 28);

    return result;
}

// 復号化処理
async function decryptData(dataBytes, password) {
    try {
        const salt = dataBytes.slice(0, 16);
        const iv = dataBytes.slice(16, 28);
        const encryptedContent = dataBytes.slice(28);

        const key = await deriveKey(password, salt);

        const decryptedContent = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            encryptedContent
        );

        const dec = new TextDecoder();
        return dec.decode(decryptedContent);
    } catch (e) {
        console.error(e);
        return null;
    }
}


// 埋め込み
async function encodeProcess() {
    try {
        const fileInput = document.getElementById('upload-encode');
        const text = document.getElementById('secret-text').value;
        const password = document.getElementById('pass-encode').value;

        if (!text) { alert("メッセージを入力してください"); return; }
        if (!password) { alert("パスワードを入力してください（必須）"); return; }

        const ctx = await loadImage(fileInput, 'canvas-encode');
        const width = ctx.canvas.width;
        const height = ctx.canvas.height;
        const imgData = ctx.getImageData(0, 0, width, height);
        const data = imgData.data;

        // 暗号化
        const encryptedBytes = await encryptData(text, password);

        // 全体サイズ(4バイト) + 暗号化済みデータ
        const lengthBytes = new Uint8Array(4);
        new DataView(lengthBytes.buffer).setUint32(0, encryptedBytes.length);
        
        const totalBytes = new Uint8Array(lengthBytes.length + encryptedBytes.length);
        totalBytes.set(lengthBytes, 0);
        totalBytes.set(encryptedBytes, 4);

        // 容量チェック
        if (totalBytes.length * 8 > data.length * 0.75) {
            alert("データ量が多すぎます。もっと大きい画像を使うか、文章を短くしてください。");
            return;
        }

        // ビット埋め込み
        let dataIndex = 0;
        let bitIndex = 0;

        for (let i = 0; i < data.length; i += 4) {
            if (dataIndex >= totalBytes.length) break;
            for (let j = 0; j < 3; j++) {
                if (dataIndex >= totalBytes.length) break;
                
                const bit = (totalBytes[dataIndex] >> (7 - bitIndex)) & 1;
                data[i + j] = (data[i + j] & 0xFE) | bit;

                bitIndex++;
                if (bitIndex == 8) {
                    bitIndex = 0;
                    dataIndex++;
                }
            }
        }

        ctx.putImageData(imgData, 0, 0);

        const link = document.createElement('a');
        link.download = 'secret_image.png';
        link.href = document.getElementById('canvas-encode').toDataURL('image/png');
        link.click();
        
    } catch (e) {
        alert("エラーが発生しました: " + e);
        console.error(e);
    }
}


// 読み取り
async function decodeProcess() {
    try {
        const fileInput = document.getElementById('upload-decode');
        const password = document.getElementById('pass-decode').value;

        if (!password) { alert("パスワードを入力してください"); return; }
        if (!fileInput.files[0]) { alert("画像を選択してください"); return; }
        
        // 画像データを読み込む
        const file = fileInput.files[0];
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        
        const img = await new Promise((resolve) => {
            const i = new Image();
            i.onload = () => resolve(i);
            i.src = URL.createObjectURL(file);
        });

        canvas.width = img.width;
        canvas.height = img.height;
        ctx.drawImage(img, 0, 0);
        const data = ctx.getImageData(0, 0, canvas.width, canvas.height).data;

        // ビット抽出
        let extractedBytes = [];
        let currentByte = 0;
        let bitIndex = 0;
        let messageLength = null;

        for (let i = 0; i < data.length; i += 4) {
            for (let j = 0; j < 3; j++) {
                const bit = data[i + j] & 1;
                currentByte = (currentByte << 1) | bit;
                bitIndex++;

                if (bitIndex == 8) {
                    extractedBytes.push(currentByte);
                    
                    if (extractedBytes.length === 4 && messageLength === null) {
                        const buffer = new Uint8Array(extractedBytes).buffer;
                        messageLength = new DataView(buffer).getUint32(0);
                        extractedBytes = [];
                    } 
                    else if (messageLength !== null && extractedBytes.length === messageLength) {
                        const result = await decryptData(new Uint8Array(extractedBytes), password);
                        
                        if (result) {
                            document.getElementById('decoded-result').value = result;
                        } else {
                            document.getElementById('decoded-result').value = "復号失敗：パスワードが間違っています。";
                        }
                        return;
                    }

                    currentByte = 0;
                    bitIndex = 0;
                }
            }
        }
        document.getElementById('decoded-result').value = "隠されたデータが見つかりませんでした。";

    } catch (e) {
        alert("エラー: " + e);
        console.error(e);
    }
}