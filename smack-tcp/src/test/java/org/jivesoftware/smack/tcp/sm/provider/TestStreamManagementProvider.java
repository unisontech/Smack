package org.jivesoftware.smack.tcp.sm.provider;

import static org.junit.Assert.assertEquals;

import java.io.IOException;

import org.jivesoftware.smack.tcp.sm.packet.StreamManagement.Enabled;
import org.jivesoftware.smack.util.PacketParserUtils;
import org.junit.Test;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

public class TestStreamManagementProvider {

	@Test
	public void testParseEnabled() throws XmlPullParserException, IOException {
		String enabledString = (new Enabled("stream-id", false)).toXML().toString();
		XmlPullParser parser = PacketParserUtils.getParserFor(enabledString);
		Enabled enabled = ParseStreamManagement.enabled(parser);

		assertEquals(enabledString, enabled.toXML().toString());
	}
}
