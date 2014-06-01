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
package org.jivesoftware.smack.tcp.sm.packet;

import org.jivesoftware.smack.packet.Packet;
import org.jivesoftware.smack.packet.XMPPError;
import org.jivesoftware.smack.util.XmlStringBuilder;

public class StreamManagement extends Packet {
    public static final String NAMESPACE = "urn:xmpp:sm:3";

    @Override
    public CharSequence toXML() {
        // TODO Auto-generated method stub
        return null;
    }

    public static class Enable extends Packet {
        public static final String ELEMENT = "enable";

        /**
         * Client's preferred maximum resumption time in seconds (optional).
         */
        private int max = -1;

        private boolean resume = false;

        public Enable(boolean resume) {
            this.resume = resume;
        }

        public Enable(boolean resume, int max) {
            this(resume);
            this.max = max;
        }

        @Override
        public CharSequence toXML() {
            XmlStringBuilder xml = new XmlStringBuilder();
            xml.halfOpenElement(ELEMENT);
            xml.xmlnsAttribute(NAMESPACE);
            if (resume) {
                xml.attribute("resume", Boolean.toString(resume));
            }
            if (max > 0) {
                xml.attribute("max", Integer.toString(max));
            }
            xml.closeEmptyElement();
            return xml;
        }
    }

    public static class Enabled extends Packet {
        public static final String ELEMENT = "enabled";

        private String id;
        private String location;
        private boolean resume = false;

        /**
         * Server's preferred maximum resumption time in seconds (optional).
         */
        private int max = -1;

        public Enabled(String id, boolean resume) {
            this.id = id;
            this.resume = resume;
        }

        public Enabled(String id, boolean resume, String location, int max) {
            this(id, resume);
            this.location = location;
            this.max = max;
        }

        @Override
        public CharSequence toXML() {
            XmlStringBuilder xml = new XmlStringBuilder();
            xml.halfOpenElement(ELEMENT);
            xml.xmlnsAttribute(NAMESPACE);
            xml.optAttribute("id", id);
            if (resume) {
                xml.attribute("resume", Boolean.toString(resume));
            }
            xml.optAttribute("location", location);
            if (max > 0) {
                xml.attribute("max", Integer.toString(max));
            }
            xml.closeEmptyElement();
            return xml;
        }
    }

    public static class Failed extends Packet {
        public static final String ELEMENT = "failed";

        private XMPPError error;

        public Failed() {
        }

        public Failed(XMPPError error) {
            this.error = error;
        }

        @Override
        public CharSequence toXML() {
            XmlStringBuilder xml = new XmlStringBuilder();
            xml.openElement(ELEMENT);
            xml.xmlnsAttribute(NAMESPACE);
            if (error != null) {
                xml.rightAngelBracket();
                xml.append(error.toXML());
                xml.closeElement(ELEMENT);
            }
            else {
                xml.closeEmptyElement();
            }
            return xml;
        }

    }

    private static abstract class AbstractResume extends Packet {

        private final long height;
        private final String previd;

        public AbstractResume(long height, String previd) {
            this.height = height;
            this.previd = previd;
        }

        abstract String getElement();

        @Override
        public final CharSequence toXML() {
            XmlStringBuilder xml = new XmlStringBuilder();
            xml.openElement(getElement());
            xml.xmlnsAttribute(NAMESPACE);
            xml.attribute("h", Long.toString(height));
            xml.attribute("previd", previd);
            xml.closeEmptyElement();
            return xml;
        }
    }

    public static class Resume extends AbstractResume {
        public Resume(long height, String previd) {
            super(height, previd);
        }

        @Override
        String getElement() {
            return "resume";
        }
    }

    public static class Resumed extends AbstractResume {
        public static final String ELEMENT = "resumed";

        public Resumed(long height, String previd) {
            super(height, previd);
        }

        @Override
        String getElement() {
            return ELEMENT;
        }
    }

    public static class AckAnswer extends Packet {
        public static final String ELEMENT = "a";

        private final long height;

        public AckAnswer(long height) {
            this.height = height;
        }

        @Override
        public CharSequence toXML() {
            XmlStringBuilder xml = new XmlStringBuilder();
            xml.openElement(ELEMENT);
            xml.xmlnsAttribute(NAMESPACE);
            xml.attribute("h", Long.toString(height));
            xml.closeEmptyElement();
            return xml;
        }
    }

    public static class AckRequest extends Packet {
        public static final String ELEMENT = "r";

        @Override
        public CharSequence toXML() {
            return '<' + ELEMENT + "xmlns='" + NAMESPACE + '\'';
        }
    }
}
