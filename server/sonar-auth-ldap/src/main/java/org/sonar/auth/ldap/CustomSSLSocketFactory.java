/*
 * SonarQube
 * Copyright (C) 2009-2020 SonarSource SA
 * mailto:info AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.sonar.auth.ldap;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.SecureRandom;

/**
 * CustomSSLSocketFactory to not verify certificate
 */
public class CustomSSLSocketFactory extends SSLSocketFactory {
    private SSLSocketFactory socketFactory;

    public CustomSSLSocketFactory() {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{new DummyTrustmanager()}, new SecureRandom());
            socketFactory = ctx.getSocketFactory();
        } catch (Exception ex) {
            ex.printStackTrace(System.err);
        }
    }

    public static SocketFactory getDefault() {
        return new CustomSSLSocketFactory();
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return socketFactory.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return socketFactory.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(Socket socket, String string, int num, boolean bool) throws IOException {
        return socketFactory.createSocket(socket, string, num, bool);
    }

    @Override
    public Socket createSocket(String string, int num) throws IOException, UnknownHostException {
        return socketFactory.createSocket(string, num);
    }

    @Override
    public Socket createSocket(String string, int num, InetAddress netAdd, int i) throws IOException, UnknownHostException {
        return socketFactory.createSocket(string, num, netAdd, i);
    }

    @Override
    public Socket createSocket(InetAddress netAdd, int num) throws IOException {
        return socketFactory.createSocket(netAdd, num);
    }

    @Override
    public Socket createSocket(InetAddress netAdd1, int num, InetAddress netAdd2, int i) throws IOException {
        return socketFactory.createSocket(netAdd1, num, netAdd2, i);
    }
}
