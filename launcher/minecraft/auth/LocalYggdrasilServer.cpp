// SPDX-License-Identifier: GPL-3.0-only
/*
 *  Fjord Launcher - Minecraft Launcher
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, version 3.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "LocalYggdrasilServer.h"

#include <QCryptographicHash>
#include <QDateTime>
#include <QFile>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QTcpServer>
#include <QTcpSocket>
#include <QUrl>
#include <QUrlQuery>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "Application.h"
#include "BuildConfig.h"
#include "FileSystem.h"
#include "minecraft/auth/AuthSession.h"
#include "minecraft/auth/MinecraftAccount.h"

namespace {

// Requests from the game are tiny; anything larger than this is not something we serve.
constexpr qsizetype MAX_REQUEST_SIZE = 64 * 1024;

// The spec recommends 4096 bits, but the key only protects textures served to a game on this
// machine, and 2048 bits keeps the one-time generation from noticeably stalling the UI.
constexpr int KEY_BITS = 2048;

EVP_PKEY* asKey(void* key)
{
    return static_cast<EVP_PKEY*>(key);
}

QByteArray readBio(BIO* bio)
{
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio, &data);
    return QByteArray(data, static_cast<qsizetype>(len));
}

QString normalizeUuid(QString uuid)
{
    return uuid.remove('-').toLower();
}

QByteArray reasonPhrase(int status)
{
    switch (status) {
        case 200:
            return "OK";
        case 204:
            return "No Content";
        case 400:
            return "Bad Request";
        case 404:
            return "Not Found";
        case 405:
            return "Method Not Allowed";
        case 413:
            return "Payload Too Large";
        default:
            return "Internal Server Error";
    }
}

}  // namespace

LocalYggdrasilServer* LocalYggdrasilServer::instance()
{
    static LocalYggdrasilServer* s_instance = nullptr;
    if (!s_instance) {
        s_instance = new LocalYggdrasilServer(FS::PathCombine(APPLICATION->dataRoot(), "offline-skins-key.pem"), APPLICATION);
    }
    return s_instance;
}

LocalYggdrasilServer::LocalYggdrasilServer(QString keyPath, QObject* parent) : QObject(parent), m_keyPath(std::move(keyPath)) {}

LocalYggdrasilServer::~LocalYggdrasilServer()
{
    EVP_PKEY_free(asKey(m_key));
}

bool LocalYggdrasilServer::setupSession(MinecraftAccount* account, AuthSession* session)
{
    const auto& skin = account->accountData()->minecraftProfile.skin;
    if (skin.data.isEmpty() || session->uuid.isEmpty()) {
        return false;
    }
    if (!ensureKey() || !ensureStarted()) {
        return false;
    }

    const QString hash = QString::fromLatin1(QCryptographicHash::hash(skin.data, QCryptographicHash::Sha256).toHex());
    m_textures.insert(hash, skin.data);

    Profile profile;
    profile.id = normalizeUuid(session->uuid);
    profile.name = session->player_name;
    profile.skinHash = hash;
    profile.slim = skin.variant.compare("SLIM", Qt::CaseInsensitive) == 0;
    m_profiles.insert(profile.id, profile);

    const QString root = rootUrl();
    session->authlib_injector_url = root;
    session->auth_server_url = root + "/authserver";
    session->account_server_url = root + "/api";
    session->session_server_url = root + "/sessionserver";
    session->services_server_url = root + "/minecraftservices";
    session->uses_custom_api_servers = true;
    session->authlib_injector_metadata = QString::fromLatin1(metadata().toBase64());
    return true;
}

bool LocalYggdrasilServer::ensureStarted()
{
    if (m_server && m_server->isListening()) {
        return true;
    }
    if (!m_server) {
        m_server = new QTcpServer(this);
        connect(m_server, &QTcpServer::newConnection, this, &LocalYggdrasilServer::onNewConnection);
    }
    if (!m_server->listen(QHostAddress::LocalHost, 0)) {
        qWarning() << "Failed to start the local Yggdrasil server for offline skins:" << m_server->errorString();
        return false;
    }
    qDebug() << "Local Yggdrasil server for offline skins listening on" << rootUrl();
    return true;
}

bool LocalYggdrasilServer::ensureKey()
{
    if (m_key) {
        return true;
    }

    const QString& keyPath = m_keyPath;
    EVP_PKEY* key = nullptr;

    QFile keyFile(keyPath);
    if (keyFile.open(QIODevice::ReadOnly)) {
        const QByteArray pem = keyFile.readAll();
        BIO* bio = BIO_new_mem_buf(pem.constData(), static_cast<int>(pem.size()));
        key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (!key) {
            qWarning() << "Offline skin signing key at" << keyPath << "is unreadable, generating a new one";
        }
    }

    if (!key) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
        if (ctx && EVP_PKEY_keygen_init(ctx) > 0 && EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, KEY_BITS) > 0) {
            EVP_PKEY_keygen(ctx, &key);
        }
        EVP_PKEY_CTX_free(ctx);
        if (!key) {
            qWarning() << "Failed to generate the offline skin signing key";
            return false;
        }

        BIO* bio = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr);
        const QByteArray pem = readBio(bio);
        BIO_free(bio);

        // Failing to persist the key only means a new one is generated next time.
        QSaveFile out(keyPath);
        if (out.open(QIODevice::WriteOnly)) {
            out.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
            out.write(pem);
            if (!out.commit()) {
                qWarning() << "Failed to save the offline skin signing key to" << keyPath;
            }
        }
    }

    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, key);
    m_publicKeyPem = QString::fromLatin1(readBio(bio));
    BIO_free(bio);

    m_key = key;
    return true;
}

QString LocalYggdrasilServer::rootUrl() const
{
    return QString("http://127.0.0.1:%1").arg(m_server->serverPort());
}

QByteArray LocalYggdrasilServer::metadata() const
{
    QJsonObject meta{
        { "serverName", QString("%1 offline skins").arg(BuildConfig.LAUNCHER_DISPLAYNAME) },
        { "implementationName", BuildConfig.LAUNCHER_DISPLAYNAME },
        { "implementationVersion", BuildConfig.printableVersionString() },
        { "feature.non_email_login", true },
    };
    QJsonObject root{
        { "meta", meta },
        { "skinDomains", QJsonArray{ "127.0.0.1", "localhost" } },
        { "signaturePublickey", m_publicKeyPem },
    };
    return QJsonDocument(root).toJson(QJsonDocument::Compact);
}

QByteArray LocalYggdrasilServer::signature(const QByteArray& data) const
{
    QByteArray result;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    size_t len = 0;
    if (ctx && EVP_DigestSignInit(ctx, nullptr, EVP_sha1(), nullptr, asKey(m_key)) > 0 &&
        EVP_DigestSignUpdate(ctx, data.constData(), static_cast<size_t>(data.size())) > 0 && EVP_DigestSignFinal(ctx, nullptr, &len) > 0) {
        result.resize(static_cast<qsizetype>(len));
        if (EVP_DigestSignFinal(ctx, reinterpret_cast<unsigned char*>(result.data()), &len) > 0) {
            result.resize(static_cast<qsizetype>(len));
        } else {
            result.clear();
        }
    }
    EVP_MD_CTX_free(ctx);
    if (result.isEmpty()) {
        qWarning() << "Failed to sign offline skin textures";
    }
    return result.toBase64();
}

QByteArray LocalYggdrasilServer::profileJson(const Profile& profile, bool signedProperties) const
{
    QJsonObject skin{ { "url", rootUrl() + "/textures/" + profile.skinHash } };
    if (profile.slim) {
        skin["metadata"] = QJsonObject{ { "model", "slim" } };
    }
    QJsonObject textures{
        { "timestamp", QDateTime::currentMSecsSinceEpoch() },
        { "profileId", profile.id },
        { "profileName", profile.name },
        { "textures", QJsonObject{ { "SKIN", skin } } },
    };
    if (signedProperties) {
        textures["signatureRequired"] = true;
    }

    const QByteArray value = QJsonDocument(textures).toJson(QJsonDocument::Compact).toBase64();
    QJsonObject property{ { "name", "textures" }, { "value", QString::fromLatin1(value) } };
    if (signedProperties) {
        property["signature"] = QString::fromLatin1(signature(value));
    }

    QJsonObject root{
        { "id", profile.id },
        { "name", profile.name },
        { "properties", QJsonArray{ property } },
    };
    return QJsonDocument(root).toJson(QJsonDocument::Compact);
}

void LocalYggdrasilServer::onNewConnection()
{
    while (auto* socket = m_server->nextPendingConnection()) {
        m_buffers.insert(socket, {});
        connect(socket, &QTcpSocket::readyRead, this, [this, socket] { onReadyRead(socket); });
        connect(socket, &QTcpSocket::disconnected, this, [this, socket] {
            m_buffers.remove(socket);
            socket->deleteLater();
        });
    }
}

void LocalYggdrasilServer::onReadyRead(QTcpSocket* socket)
{
    if (!m_buffers.contains(socket)) {
        return;  // already answered
    }
    QByteArray& buffer = m_buffers[socket];
    buffer += socket->readAll();
    if (buffer.size() > MAX_REQUEST_SIZE) {
        m_buffers.remove(socket);
        respond(socket, 413);
        return;
    }

    const qsizetype headerEnd = buffer.indexOf("\r\n\r\n");
    if (headerEnd < 0) {
        return;  // wait for the rest of the headers
    }

    const QList<QByteArray> lines = buffer.left(headerEnd).split('\n');
    const QList<QByteArray> requestLine = lines.first().trimmed().split(' ');
    if (requestLine.size() < 2) {
        m_buffers.remove(socket);
        respond(socket, 400);
        return;
    }

    qsizetype contentLength = 0;
    for (qsizetype i = 1; i < lines.size(); i++) {
        const QByteArray line = lines[i].trimmed();
        const qsizetype colon = line.indexOf(':');
        if (colon > 0 && line.left(colon).trimmed().toLower() == "content-length") {
            contentLength = line.mid(colon + 1).trimmed().toLongLong();
        }
    }

    const qsizetype bodyStart = headerEnd + 4;
    if (contentLength < 0 || bodyStart + contentLength > MAX_REQUEST_SIZE) {
        m_buffers.remove(socket);
        respond(socket, 413);
        return;
    }
    if (buffer.size() < bodyStart + contentLength) {
        return;  // wait for the rest of the body
    }

    const QByteArray method = requestLine[0];
    const QString target = QString::fromUtf8(requestLine[1]);
    const QByteArray body = buffer.mid(bodyStart, contentLength);
    m_buffers.remove(socket);
    handleRequest(socket, method, target, body);
}

void LocalYggdrasilServer::handleRequest(QTcpSocket* socket, const QByteArray& method, const QString& target, const QByteArray& body)
{
    const QUrl url(target);
    const QString path = url.path();
    const QUrlQuery query(url);

    static const QString profilePrefix = "/sessionserver/session/minecraft/profile/";
    static const QString texturePrefix = "/textures/";

    if (method == "GET" && (path.isEmpty() || path == "/")) {
        respond(socket, 200, metadata());
        return;
    }

    if (method == "GET" && path.startsWith(profilePrefix)) {
        const auto it = m_profiles.constFind(normalizeUuid(path.mid(profilePrefix.size())));
        if (it == m_profiles.constEnd()) {
            respond(socket, 204);
            return;
        }
        const bool wantsSignature = query.queryItemValue("unsigned") == "false";
        respond(socket, 200, profileJson(*it, wantsSignature));
        return;
    }

    if (method == "GET" && path.startsWith(texturePrefix)) {
        const auto it = m_textures.constFind(path.mid(texturePrefix.size()));
        if (it == m_textures.constEnd()) {
            respond(socket, 404);
            return;
        }
        respond(socket, 200, *it, "image/png");
        return;
    }

    if (method == "POST" && path == "/sessionserver/session/minecraft/join") {
        respond(socket, 204);
        return;
    }

    if (method == "GET" && path == "/sessionserver/session/minecraft/hasJoined") {
        const QString username = query.queryItemValue("username");
        for (const auto& profile : m_profiles) {
            if (profile.name == username) {
                respond(socket, 200, profileJson(profile, true));
                return;
            }
        }
        respond(socket, 204);
        return;
    }

    if (method == "POST" && path == "/api/profiles/minecraft") {
        QJsonArray result;
        for (const auto& name : QJsonDocument::fromJson(body).array()) {
            for (const auto& profile : m_profiles) {
                if (profile.name.compare(name.toString(), Qt::CaseInsensitive) == 0) {
                    result.append(QJsonObject{ { "id", profile.id }, { "name", profile.name } });
                    break;
                }
            }
        }
        respond(socket, 200, QJsonDocument(result).toJson(QJsonDocument::Compact));
        return;
    }

    respond(socket, 404);
}

void LocalYggdrasilServer::respond(QTcpSocket* socket, int status, const QByteArray& body, const QByteArray& contentType)
{
    QByteArray response = "HTTP/1.1 " + QByteArray::number(status) + ' ' + reasonPhrase(status) + "\r\n";
    if (status != 204) {
        response += "Content-Type: " + contentType + "\r\n";
        response += "Content-Length: " + QByteArray::number(body.size()) + "\r\n";
    }
    response += "Connection: close\r\n\r\n";
    if (status != 204) {
        response += body;
    }
    socket->write(response);
    socket->disconnectFromHost();
}
