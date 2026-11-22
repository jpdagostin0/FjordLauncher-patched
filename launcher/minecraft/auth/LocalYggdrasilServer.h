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

#pragma once

#include <QByteArray>
#include <QHash>
#include <QObject>
#include <QString>

class QTcpServer;
class QTcpSocket;
struct AuthSession;
class MinecraftAccount;

/**
 * A minimal Yggdrasil API server, bound to localhost, that serves skins for offline accounts.
 *
 * The game is pointed at it through authlib-injector (or Loki). It implements just enough of the
 * authlib-injector Yggdrasil server specification for the game to fetch the local player's
 * profile and textures: API metadata, profile lookup (with SHA1withRSA-signed properties),
 * name lookup, join/hasJoined and the texture images themselves.
 */
class LocalYggdrasilServer : public QObject {
    Q_OBJECT
   public:
    //! The launcher-wide server, with its signing key stored in the launcher's data directory.
    static LocalYggdrasilServer* instance();

    //! The signing key is loaded from (or generated and saved to) keyPath on first use.
    explicit LocalYggdrasilServer(QString keyPath, QObject* parent = nullptr);
    ~LocalYggdrasilServer() override;

    /**
     * Registers the account's skin with the server (starting the server if needed) and rewrites
     * the session so the game uses this server as its API root.
     * Returns false and leaves the session untouched if the account has no skin or the server
     * could not be started.
     */
    bool setupSession(MinecraftAccount* account, AuthSession* session);

   private:
    struct Profile {
        QString id;  // unhyphenated UUID
        QString name;
        QString skinHash;  // sha256 hex of the PNG
        bool slim = false;
    };

    bool ensureStarted();
    bool ensureKey();
    QString rootUrl() const;
    QByteArray metadata() const;
    QByteArray signature(const QByteArray& data) const;
    QByteArray profileJson(const Profile& profile, bool signedProperties) const;

    void onNewConnection();
    void onReadyRead(QTcpSocket* socket);
    void handleRequest(QTcpSocket* socket, const QByteArray& method, const QString& target, const QByteArray& body);
    static void respond(QTcpSocket* socket, int status, const QByteArray& body = {}, const QByteArray& contentType = "application/json");

    QString m_keyPath;
    QTcpServer* m_server = nullptr;
    void* m_key = nullptr;  // EVP_PKEY*, kept opaque to avoid leaking OpenSSL headers
    QString m_publicKeyPem;
    QHash<QString, Profile> m_profiles;     // keyed by unhyphenated UUID
    QHash<QString, QByteArray> m_textures;  // keyed by sha256 hex
    QHash<QTcpSocket*, QByteArray> m_buffers;
};
