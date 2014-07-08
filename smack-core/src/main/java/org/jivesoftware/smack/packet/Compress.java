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

package org.jivesoftware.smack.packet;

import org.jivesoftware.smack.util.XmlStringBuilder;

public class Compress extends Packet {

    public static final String ELEMENT = "compress";
    public static final String NAMESPACE = "http://jabber.org/protocol/compress";

    public static final String METHOD = "method";

    private final String method;

    public Compress(String method) {
        this.method = method;
    }

    @Override
    public XmlStringBuilder toXML() {
        XmlStringBuilder xml = new XmlStringBuilder();
        xml.openElement(ELEMENT);
        xml.openElement(METHOD).escape(method).closeElement(METHOD);
        xml.closeElement(ELEMENT);
        return xml;
    }

}
