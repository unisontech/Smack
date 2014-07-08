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
import org.jivesoftware.smack.packet.PacketExtension;
import org.jivesoftware.smack.packet.XMPPError;
import org.jivesoftware.smack.util.XmlStringBuilder;

public class StreamManagement {
    public static final String NAMESPACE = "urn:xmpp:sm:3";

    public static class StreamManagementFeature implements PacketExtension {

        public static final String ELEMENT = "sm";

        @Override
        public String getElementName() {
            return ELEMENT;
        }

        @Override
        public String getNamespace() {
            return NAMESPACE;
        }

        @Override
        public CharSequence toXML() {
            XmlStringBuilder xml = new XmlStringBuilder(this);
            xml.rightAngelBracket();
            return xml;
        }
    }

    public static abstract class AbstractEnable extends Packet {

        /**
         * Preferred maximum resumption time in seconds (optional).
         */
        protected int max = -1;

        protected boolean resume = false;

        protected void maybeAddResumeAttributeTo(XmlStringBuilder xml) {
            if (resume) {
                // XEP 198 never mentions the case where resume='false', it's either set to true or
                // not set at all. We reflect this in this code part
                xml.attribute("resume", "true");
            }
        }

        protected void maybeAddMaxAttributeTo(XmlStringBuilder xml) {
            if (max > 0) {
                xml.attribute("max", Integer.toString(max));
            }
        }

        public boolean resumeSet() {
            return resume;
        }

        /**
         * Return the max resumption time in seconds.
         * @return the max resumption time in seconds
         */
        public int getMaxResumptionTime() {
            return max;
        }

        @Override
        public abstract CharSequence toXML();

    }

    public static class Enable extends AbstractEnable {
        public static final String ELEMENT = "enable";

        public Enable() {
        }

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
            maybeAddResumeAttributeTo(xml);
            maybeAddMaxAttributeTo(xml);
            xml.closeEmptyElement();
            return xml;
        }
    }

    public static class Enabled extends AbstractEnable {
        public static final String ELEMENT = "enabled";

        /**
         * TODO javadoc
         */
        private final String id;

        /**
         * TODO javadoc
         */
        private final String location;

        public Enabled(String id, boolean resume) {
            this(id, resume, null, -1);
        }

        public Enabled(String id, boolean resume, String location, int max) {
            this.id = id;
            this.resume = resume;
            this.location = location;
            this.max = max;
        }

        public String getId() {
            return id;
        }

        public String getLocation() {
            return location;
        }

        @Override
        public CharSequence toXML() {
            XmlStringBuilder xml = new XmlStringBuilder();
            xml.halfOpenElement(ELEMENT);
            xml.xmlnsAttribute(NAMESPACE);
            xml.optAttribute("id", id);
            maybeAddResumeAttributeTo(xml);
            xml.optAttribute("location", location);
            maybeAddMaxAttributeTo(xml);
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

        public XMPPError getXMPPError() {
            return error;
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

        private final long handledCount;
        private final String previd;

        public AbstractResume(long handledCount, String previd) {
            this.handledCount = handledCount;
            this.previd = previd;
        }

        abstract String getElement();

        public long getHandledCount() {
            return handledCount;
        }

        public String getPrevId() {
            return previd;
        }

        @Override
        public final CharSequence toXML() {
            XmlStringBuilder xml = new XmlStringBuilder();
            xml.openElement(getElement());
            xml.xmlnsAttribute(NAMESPACE);
            xml.attribute("h", Long.toString(handledCount));
            xml.attribute("previd", previd);
            xml.closeEmptyElement();
            return xml;
        }
    }

    public static class Resume extends AbstractResume {
        public static final String ELEMENT = "resume";

        public Resume(long handledCount, String previd) {
            super(handledCount, previd);
        }

        @Override
        String getElement() {
            return ELEMENT;
        }
    }

    public static class Resumed extends AbstractResume {
        public static final String ELEMENT = "resumed";

        public Resumed(long handledCount, String previd) {
            super(handledCount, previd);
        }

        @Override
        String getElement() {
            return ELEMENT;
        }
    }

    public static class AckAnswer extends Packet {
        public static final String ELEMENT = "a";

        private final long handledCount;

        public AckAnswer(long handledCount) {
            this.handledCount = handledCount;
        }

        public long getHandledCount() {
            return handledCount;
        }

        @Override
        public CharSequence toXML() {
            XmlStringBuilder xml = new XmlStringBuilder();
            xml.openElement(ELEMENT);
            xml.xmlnsAttribute(NAMESPACE);
            xml.attribute("h", Long.toString(handledCount));
            xml.closeEmptyElement();
            return xml;
        }
    }

    public static class AckRequest extends Packet {
        public static final String ELEMENT = "r";

        @Override
        public CharSequence toXML() {
            return '<' + ELEMENT + "xmlns='" + NAMESPACE + "'/>";
        }
    }
}
