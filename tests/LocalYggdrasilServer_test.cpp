#include <QBuffer>
#include <QEventLoop>
#include <QImage>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QTemporaryDir>
#include <QTest>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <minecraft/auth/AuthSession.h>
#include <minecraft/auth/LocalYggdrasilServer.h>
#include <minecraft/auth/MinecraftAccount.h>

namespace {

struct Response {
    int status = 0;
    QByteArray contentType;
    QByteArray body;
};

Response request(const QString& url, const QByteArray& postBody = {})
{
    QNetworkAccessManager nam;
    QNetworkRequest req{ QUrl(url) };
    QNetworkReply* reply = nullptr;
    if (postBody.isNull()) {
        reply = nam.get(req);
    } else {
        req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
        reply = nam.post(req, postBody);
    }
    QEventLoop loop;
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    loop.exec();
    Response out;
    out.status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
    out.contentType = reply->header(QNetworkRequest::ContentTypeHeader).toByteArray();
    out.body = reply->readAll();
    reply->deleteLater();
    return out;
}

QByteArray makeSkinPng()
{
    QImage image(64, 64, QImage::Format_ARGB32);
    image.fill(Qt::red);
    QByteArray png;
    QBuffer buffer(&png);
    buffer.open(QIODevice::WriteOnly);
    image.save(&buffer, "PNG");
    return png;
}

bool verifySha1WithRsa(const QString& publicKeyPem, const QByteArray& data, const QByteArray& base64Signature)
{
    const QByteArray pem = publicKeyPem.toLatin1();
    BIO* bio = BIO_new_mem_buf(pem.constData(), static_cast<int>(pem.size()));
    EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!key) {
        return false;
    }
    const QByteArray sig = QByteArray::fromBase64(base64Signature);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    const bool ok =
        EVP_DigestVerifyInit(ctx, nullptr, EVP_sha1(), nullptr, key) > 0 &&
        EVP_DigestVerifyUpdate(ctx, data.constData(), static_cast<size_t>(data.size())) > 0 &&
        EVP_DigestVerifyFinal(ctx, reinterpret_cast<const unsigned char*>(sig.constData()), static_cast<size_t>(sig.size())) == 1;
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);
    return ok;
}

}  // namespace

class LocalYggdrasilServerTest : public QObject {
    Q_OBJECT

   private slots:
    void test_noSkinLeavesSessionAlone()
    {
        QTemporaryDir dir;
        LocalYggdrasilServer server(dir.filePath("key.pem"));
        auto account = MinecraftAccount::createOffline("Plain");
        auto session = std::make_shared<AuthSession>();
        account->fillSession(session);

        QVERIFY(!server.setupSession(account.get(), session.get()));
        QVERIFY(!session->uses_custom_api_servers);
        QVERIFY(session->authlib_injector_url.isEmpty());
    }

    void test_servesSignedSkin()
    {
        QTemporaryDir dir;
        const QString keyPath = dir.filePath("key.pem");
        LocalYggdrasilServer server(keyPath);

        const QByteArray png = makeSkinPng();
        auto account = MinecraftAccount::createOffline("Steve2");
        account->setOfflineSkin(png, "SLIM");
        auto session = std::make_shared<AuthSession>();
        account->fillSession(session);

        QVERIFY(server.setupSession(account.get(), session.get()));
        QVERIFY(session->uses_custom_api_servers);
        const QString root = session->authlib_injector_url;
        QVERIFY(root.startsWith("http://127.0.0.1:"));
        QCOMPARE(session->session_server_url, root + "/sessionserver");

        // API metadata, and the prefetched copy handed to authlib-injector matches it
        auto meta = request(root + "/");
        QCOMPARE(meta.status, 200);
        QCOMPARE(QByteArray::fromBase64(session->authlib_injector_metadata.toLatin1()), meta.body);
        const auto metaObj = QJsonDocument::fromJson(meta.body).object();
        QVERIFY(metaObj["skinDomains"].toArray().contains(QJsonValue("127.0.0.1")));
        const QString publicKey = metaObj["signaturePublickey"].toString();
        QVERIFY(publicKey.startsWith("-----BEGIN PUBLIC KEY-----"));
        QVERIFY(QFile::exists(keyPath));

        // signed profile lookup
        auto profile = request(root + "/sessionserver/session/minecraft/profile/" + session->uuid + "?unsigned=false");
        QCOMPARE(profile.status, 200);
        const auto profileObj = QJsonDocument::fromJson(profile.body).object();
        QCOMPARE(profileObj["id"].toString(), session->uuid);
        QCOMPARE(profileObj["name"].toString(), QString("Steve2"));
        const auto property = profileObj["properties"].toArray().first().toObject();
        QCOMPARE(property["name"].toString(), QString("textures"));
        const QByteArray value = property["value"].toString().toLatin1();
        QVERIFY(verifySha1WithRsa(publicKey, value, property["signature"].toString().toLatin1()));
        QVERIFY(!verifySha1WithRsa(publicKey, value + "x", property["signature"].toString().toLatin1()));

        const auto textures = QJsonDocument::fromJson(QByteArray::fromBase64(value)).object();
        QCOMPARE(textures["profileId"].toString(), session->uuid);
        const auto skin = textures["textures"].toObject()["SKIN"].toObject();
        QCOMPARE(skin["metadata"].toObject()["model"].toString(), QString("slim"));
        const QString skinUrl = skin["url"].toString();
        QVERIFY(skinUrl.startsWith(root + "/textures/"));

        // unsigned by default, as the spec requires
        auto unsignedProfile = request(root + "/sessionserver/session/minecraft/profile/" + session->uuid);
        QCOMPARE(unsignedProfile.status, 200);
        QVERIFY(!QJsonDocument::fromJson(unsignedProfile.body).object()["properties"].toArray().first().toObject().contains("signature"));

        // the texture itself
        auto texture = request(skinUrl);
        QCOMPARE(texture.status, 200);
        QCOMPARE(texture.contentType, QByteArray("image/png"));
        QCOMPARE(texture.body, png);

        // unknown things
        QCOMPARE(request(root + "/sessionserver/session/minecraft/profile/00000000000000000000000000000000").status, 204);
        QCOMPARE(request(root + "/textures/nope").status, 404);
        QCOMPARE(request(root + "/minecraftservices/player/attributes").status, 404);

        // name lookup and join/hasJoined
        auto names = request(root + "/api/profiles/minecraft", R"(["steve2","nobody"])");
        QCOMPARE(names.status, 200);
        const auto namesArr = QJsonDocument::fromJson(names.body).array();
        QCOMPARE(namesArr.size(), 1);
        QCOMPARE(namesArr.first().toObject()["id"].toString(), session->uuid);
        QCOMPARE(request(root + "/sessionserver/session/minecraft/join", "{}").status, 204);
        QCOMPARE(request(root + "/sessionserver/session/minecraft/hasJoined?username=Steve2&serverId=x").status, 200);
        QCOMPARE(request(root + "/sessionserver/session/minecraft/hasJoined?username=Alex&serverId=x").status, 204);

        // the key is persisted and reused
        LocalYggdrasilServer second(keyPath);
        auto session2 = std::make_shared<AuthSession>();
        account->fillSession(session2);
        QVERIFY(second.setupSession(account.get(), session2.get()));
        const auto meta2 = QJsonDocument::fromJson(request(session2->authlib_injector_url + "/").body).object();
        QCOMPARE(meta2["signaturePublickey"].toString(), publicKey);
    }

    void test_clearSkin()
    {
        auto account = MinecraftAccount::createOffline("Steve3");
        account->setOfflineSkin(makeSkinPng(), "CLASSIC");
        QVERIFY(!account->accountData()->minecraftProfile.skin.data.isEmpty());
        QVERIFY(account->accountData()->minecraftProfile.skin.url.startsWith("offline-skin:"));
        account->setOfflineSkin({}, {});
        QVERIFY(account->accountData()->minecraftProfile.skin.data.isEmpty());
        QVERIFY(account->accountData()->minecraftProfile.skin.url.isEmpty());
    }
};

QTEST_GUILESS_MAIN(LocalYggdrasilServerTest)

#include "LocalYggdrasilServer_test.moc"
