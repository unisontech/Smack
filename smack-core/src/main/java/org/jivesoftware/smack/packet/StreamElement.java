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

/**
 * Base class for Stream elements. Everything that is not a stanza (RFC 6120 8.), ie. message,
 * presence and iq, should sublcass this class instead of {@link Packet}.
 * 
 * @author Florian Schmaus
 */
public abstract class StreamElement {

    /**
     * Returns the object as XML. Every concrete extension of StreamElement must implement
     * this method. In addition to writing out packet-specific data, every sub-class
     * should also write out the error and the extensions data if they are defined.
     *
     * @return the XML format of the object as a CharSequence.
     */
    public abstract CharSequence toXML();

}
