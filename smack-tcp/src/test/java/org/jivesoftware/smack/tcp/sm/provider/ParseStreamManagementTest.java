package org.jivesoftware.smack.tcp.sm.provider;

import com.jamesmurty.utils.XMLBuilder;
import org.jivesoftware.smack.packet.XMPPError;
import org.jivesoftware.smack.tcp.sm.packet.StreamManagement;
import org.jivesoftware.smack.util.PacketParserUtils;
import org.junit.Test;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.util.Properties;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

public class ParseStreamManagementTest {
    private static final Properties outputProperties = initOutputProperties();

    @Test
    public void testParseEnabled() throws Exception {
        String stanzaID = "zid615d9";
        boolean resume = true;
        String location = "test";
        int max = 42;

        String enabledStanza = XMLBuilder.create("enabled")
                .a("xmlns", "urn:xmpp:sm:3")
                .a("id", "zid615d9")
                .a("resume", String.valueOf(resume))
                .a("location", location)
                .a("max", String.valueOf(max))
                .asString(outputProperties);

        StreamManagement.Enabled enabledPacket = ParseStreamManagement.enabled(
                PacketParserUtils.getParserFor(enabledStanza));

        assertThat(enabledPacket, is(notNullValue()));
        assertThat(enabledPacket.getId(), equalTo(stanzaID));
        assertThat(enabledPacket.getLocation(), equalTo(location));
        assertThat(enabledPacket.isResumeSet(), equalTo(resume));
        assertThat(enabledPacket.getMaxResumptionTime(), equalTo(max));
    }


    @Test
    public void testParseEnabledInvariant() throws XmlPullParserException, IOException {
        String enabledString = (new StreamManagement.Enabled("stream-id", false)).toXML().toString();
        XmlPullParser parser = PacketParserUtils.getParserFor(enabledString);
        StreamManagement.Enabled enabled = ParseStreamManagement.enabled(parser);

        assertEquals(enabledString, enabled.toXML().toString());
    }

    @Test
    public void testParseFailed() throws Exception {
        String failedStanza = XMLBuilder.create("failed")
                .a("xmlns", "urn:xmpp:sm:3")
                .asString(outputProperties);

        StreamManagement.Failed failedPacket = ParseStreamManagement.failed(
                PacketParserUtils.getParserFor(failedStanza));

        assertThat(failedPacket, is(notNullValue()));
        XMPPError error = failedPacket.getXMPPError();

        assertThat(error, is(notNullValue()));
        assertThat(error.getCondition(), equalTo("unknown"));
    }

    @Test
    public void testParseFailedError() throws Exception {
        String errorCondition = "failure";

        String failedStanza = XMLBuilder.create("failed")
                .a("xmlns", "urn:xmpp:sm:3")
                .element(errorCondition, XMPPError.NAMESPACE)
                .asString(outputProperties);

        System.err.println(failedStanza);

        StreamManagement.Failed failedPacket = ParseStreamManagement.failed(
                PacketParserUtils.getParserFor(failedStanza));

        assertThat(failedPacket, is(notNullValue()));
        XMPPError error = failedPacket.getXMPPError();

        assertThat(error, is(notNullValue()));
        assertThat(error.getCondition(), equalTo(errorCondition));
    }

    @Test
    public void testParseResumed() throws Exception {
        long handledPackets = 42;
        String previousID = "zid615d9";

        String resumedStanza = XMLBuilder.create("resumed")
                .a("xmlns", "urn:xmpp:sm:3")
                .a("h", String.valueOf(handledPackets))
                .a("previd", previousID)
                .asString(outputProperties);

        StreamManagement.Resumed resumedPacket = ParseStreamManagement.resumed(
                PacketParserUtils.getParserFor(resumedStanza));

        assertThat(resumedPacket, is(notNullValue()));
        assertThat(resumedPacket.getHandledCount(), equalTo(handledPackets));
        assertThat(resumedPacket.getPrevId(), equalTo(previousID));
    }

    @Test
    public void testParseAckAnswer() throws Exception {
        long handledPackets = 42 + 42;

        String ackStanza = XMLBuilder.create("a")
                .a("xmlns", "urn:xmpp:sm:3")
                .a("h", String.valueOf(handledPackets))
                .asString(outputProperties);

        StreamManagement.AckAnswer acknowledgementPacket = ParseStreamManagement.ackAnswer(
                PacketParserUtils.getParserFor(ackStanza));

        assertThat(acknowledgementPacket, is(notNullValue()));
        assertThat(acknowledgementPacket.getHandledCount(), equalTo(handledPackets));
    }


    private static Properties initOutputProperties() {
        Properties properties = new Properties();
        properties.put(javax.xml.transform.OutputKeys.OMIT_XML_DECLARATION, "yes");
        return properties;
    }
}