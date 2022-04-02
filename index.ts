import {
  KMSClient,
  KMSClientConfig,
  SignCommand,
  SignCommandInput,
  SigningAlgorithmSpec,
  GetPublicKeyCommand,
  GetPublicKeyCommandInput,
  VerifyCommand,
  VerifyCommandInput,
} from '@aws-sdk/client-kms';

/**
 * 非対称キータイプを利用する想定
 */
const keyId = process.env.KMS_KEY_ID;
const target = 'abcdefghijklmnopqrstuvwxyz';
// Uint8Array で渡してencode
const message = new TextEncoder().encode(target);
const config: KMSClientConfig = {
  // MEMO: 実際は環境変数などから access_key, secret_access_key, region を設定
  // credentials: {
  //   accessKeyId: '',
  //   secretAccessKey: '',
  // },
  // region: 'ap-northeast-1',
  tls: true,
  maxAttempts: 2,
};
const client = new KMSClient(config);

const ginput: GetPublicKeyCommandInput = {
  KeyId: keyId,
};
const gcommand = new GetPublicKeyCommand(ginput);

client
  .send(gcommand)
  .then((result) => {
    console.log(
      `publickey: ${Buffer.from(
        new TextDecoder().decode(result.PublicKey)
      ).toString('base64')}\n`
    );
  })
  .catch((err) => {
    console.error(`get public key error: ${err}`);
  });

const signinput: SignCommandInput = {
  KeyId: keyId,
  Message: message,
  // 4096 byte を超える場合はハッシュダイジェストをMessageに指定、MessageType に DIGEST を指定
  MessageType: 'RAW',
  SigningAlgorithm: SigningAlgorithmSpec.RSASSA_PSS_SHA_256,
};

const scommand = new SignCommand(signinput);
client
  .send(scommand)
  .then((result) => {
    const signature = Buffer.from(
      new TextDecoder().decode(result.Signature)
    ).toString('base64');

    console.log(`signature: ${signature}`);

    // verify まで一貫して実施してみる
    // 実際は分けて実行する
    const verifyinput: VerifyCommandInput = {
      KeyId: keyId,
      Signature: result.Signature,
      Message: message,
      SigningAlgorithm: SigningAlgorithmSpec.RSASSA_PSS_SHA_256,
    };
    const vcommand = new VerifyCommand(verifyinput);
    client
      .send(vcommand)
      .then((result) => {
        console.log(`verifyResult: ${result.SignatureValid}`);
      })
      .catch((err) => {
        console.error(`verify error: ${err}`);
      });
  })
  .catch((err) => {
    console.error(`sign error: ${err}`);
  });
