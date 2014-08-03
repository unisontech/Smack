/**
 *
 * Copyright © 2014 Florian Schmaus
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jivesoftware.smack;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;

import org.jivesoftware.smack.SmackException.NoResponseException;
import org.jivesoftware.smack.SmackException.NotConnectedException;
import org.jivesoftware.smack.packet.Packet;

public class SynchronizationPoint<E extends Exception> {

    private final AbstractXMPPConnection connection;
    private final Lock connectionLock;
    private final Condition condition;

    private State state;
    private E failureException;

    public SynchronizationPoint(AbstractXMPPConnection connection) {
        this.connection = connection;
        this.connectionLock = connection.getConnectionLock();
        this.condition = connection.getConnectionLock().newCondition();
    }

    public void sendRequestAndWaitForResponse(Packet request) throws E, NoResponseException,
                    NotConnectedException {
        state = State.NoResponse;
        connectionLock.lock();
        try {
            if (request != null) {
                connection.sendPacket(request);
            }
            try {
                condition.await(connection.getPacketReplyTimeout(), TimeUnit.MILLISECONDS);
            }
            catch (InterruptedException e) {
                // TODO
            }
        }
        finally {
            connectionLock.unlock();
        }
        switch (state) {
        case NoResponse:
            throw new NoResponseException();
        case Failure:
            throw failureException;
        default:
            // Success, do nothing
        }
    }

    public void reportSuccess() {
        connectionLock.lock();
        try {
            state = State.Success;
            condition.signal();
        }
        finally {
            connectionLock.unlock();
        }
    }

    public void reportFailure(E failureException) {
        connectionLock.lock();
        try {
            state = State.Failure;
            this.failureException = failureException;
            condition.signal();
        }
        finally {
            connectionLock.unlock();
        }
    }

    private enum State {
        Success,
        Failure,
        NoResponse
    }
}
