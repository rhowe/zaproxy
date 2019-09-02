/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Copyright 2014 The ZAP Development Team
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
package org.zaproxy.zap.eventBus;

import static java.util.Arrays.asList;
import static java.util.Collections.emptyList;

import java.security.InvalidParameterException;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import org.apache.log4j.Logger;

/**
 * A very simple event bus
 *
 * @author simon
 */
public class SimpleEventBus implements EventBus {

    private Map<String, RegisteredPublisher> nameToPublisher = new HashMap<>();
    private List<RegisteredConsumer> danglingConsumers = new ArrayList<>();

    /**
     * The {@code Lock} for registration management (register and unregister) of publishers and
     * consumers.
     */
    private final Lock regMgmtLock = new ReentrantLock(true);

    private static Logger log = Logger.getLogger(SimpleEventBus.class);

    @Override
    public void registerPublisher(EventPublisher publisher, String... eventTypes) {
        if (publisher == null) {
            throw new InvalidParameterException("Publisher must not be null");
        }
        if (eventTypes == null || eventTypes.length == 0) {
            throw new InvalidParameterException("At least one event type must be specified");
        }
        regMgmtLock.lock();
        try {
            final String publisherName = publisher.getPublisherName();
            if (this.nameToPublisher.get(publisherName) != null) {
                throw new InvalidParameterException(
                        "Publisher with name "
                                + publisherName
                                + " already registered by "
                                + this.nameToPublisher
                                        .get(publisherName)
                                        .getPublisher()
                                        .getClass()
                                        .getCanonicalName());
            }
            log.debug("registerPublisher " + publisherName);

            RegisteredPublisher regProd = new RegisteredPublisher(publisher, asList(eventTypes));

            // Check to see if there are any cached consumers
            danglingConsumers.removeIf(
                    regCon -> {
                        if (regCon.getPublisherName().equals(publisherName)) {
                            regProd.addConsumer(regCon);
                            return true;
                        }
                        return false;
                    });
            this.nameToPublisher.put(publisherName, regProd);
        } finally {
            regMgmtLock.unlock();
        }
    }

    @Override
    public void unregisterPublisher(EventPublisher publisher) {
        if (publisher == null) {
            throw new InvalidParameterException("Publisher must not be null");
        }

        regMgmtLock.lock();
        try {
            final String publisherName = publisher.getPublisherName();
            log.debug("unregisterPublisher " + publisherName);
            if (nameToPublisher.remove(publisherName) == null) {
                throw new InvalidParameterException(
                        "Publisher with name " + publisherName + " not registered");
            }
        } finally {
            regMgmtLock.unlock();
        }
    }

    @Override
    public void registerConsumer(EventConsumer consumer, String publisherName) {
        this.registerConsumer(consumer, publisherName, (String[]) null);
    }

    @Override
    public void registerConsumer(
            EventConsumer consumer, String publisherName, String... eventTypes) {
        if (consumer == null) {
            throw new InvalidParameterException("Consumer must not be null");
        }

        final List<String> eventTypesList = eventTypes == null ? emptyList() : asList(eventTypes);

        regMgmtLock.lock();
        try {
            log.debug(
                    "registerConsumer "
                            + consumer.getClass().getCanonicalName()
                            + " for "
                            + publisherName);
            RegisteredPublisher publisher = this.nameToPublisher.get(publisherName);
            if (publisher == null) {
                // Cache until the publisher registers
                this.danglingConsumers.add(
                        new RegisteredConsumer(consumer, eventTypesList, publisherName));
            } else {
                publisher.addConsumer(new RegisteredConsumer(consumer, eventTypesList));
            }
        } finally {
            regMgmtLock.unlock();
        }
    }

    @Override
    public void unregisterConsumer(EventConsumer consumer) {
        if (consumer == null) {
            throw new InvalidParameterException("Consumer must not be null");
        }

        regMgmtLock.lock();
        try {
            log.debug("unregisterConsumer " + consumer.getClass().getCanonicalName());
            nameToPublisher.forEach((key, value) -> value.removeConsumer(consumer));
            // Check to see if its cached waiting for a publisher
            removeDanglingConsumer(consumer);
        } finally {
            regMgmtLock.unlock();
        }
    }

    private void removeDanglingConsumer(EventConsumer consumer) {
        danglingConsumers.removeIf(
                registeredConsumer -> registeredConsumer.getConsumer().equals(consumer));
    }

    @Override
    public void unregisterConsumer(EventConsumer consumer, String publisherName) {
        if (consumer == null) {
            throw new InvalidParameterException("Consumer must not be null");
        }

        regMgmtLock.lock();
        try {
            log.debug(
                    "unregisterConsumer "
                            + consumer.getClass().getCanonicalName()
                            + " for "
                            + publisherName);
            RegisteredPublisher publisher = this.nameToPublisher.get(publisherName);
            if (publisher == null) {
                // Check to see if its cached waiting for the publisher
                removeDanglingConsumer(consumer);
            } else {
                publisher.removeConsumer(consumer);
            }
        } finally {
            regMgmtLock.unlock();
        }
    }

    @Override
    public void publishSyncEvent(EventPublisher publisher, Event event) {
        if (publisher == null) {
            throw new InvalidParameterException("Publisher must not be null");
        }

        final String publisherName = publisher.getPublisherName();
        RegisteredPublisher regPublisher = this.nameToPublisher.get(publisherName);
        if (regPublisher == null) {
            throw new InvalidParameterException("Publisher not registered: " + publisherName);
        }
        log.debug("publishSyncEvent " + event.getEventType() + " from " + publisherName);
        if (regPublisher.getEventTypes().stream()
                .noneMatch(type -> event.getEventType().equals(type))) {
            throw new InvalidParameterException(
                    "Event type: "
                            + event.getEventType()
                            + " not registered for publisher: "
                            + publisherName);
        }

        for (RegisteredConsumer regCon : regPublisher.getConsumers()) {
            if (regCon.getEventTypes().stream()
                    .anyMatch(type -> event.getEventType().equals(type))) {
                try {
                    regCon.getConsumer().eventReceived(event);
                } catch (Exception e) {
                    log.error(e.getMessage(), e);
                }
            }
        }
    }

    private static class RegisteredConsumer {
        private EventConsumer consumer;
        private List<String> eventTypes;
        private String publisherName;

        RegisteredConsumer(EventConsumer consumer, List<String> eventTypes) {
            this.consumer = consumer;
            this.eventTypes = eventTypes;
        }

        RegisteredConsumer(EventConsumer consumer, List<String> eventTypes, String publisherName) {
            this.consumer = consumer;
            this.eventTypes = eventTypes;
            this.publisherName = publisherName;
        }

        public EventConsumer getConsumer() {
            return consumer;
        }

        List<String> getEventTypes() {
            return eventTypes;
        }

        public String getPublisherName() {
            return publisherName;
        }
    }

    private static class RegisteredPublisher {
        private EventPublisher publisher;
        private List<String> eventTypes;
        private List<RegisteredConsumer> consumers = new CopyOnWriteArrayList<>();

        RegisteredPublisher(EventPublisher publisher, List<String> eventTypes) {
            super();
            this.publisher = publisher;
            this.eventTypes = eventTypes;
        }

        public EventPublisher getPublisher() {
            return publisher;
        }

        List<String> getEventTypes() {
            return eventTypes;
        }

        public List<RegisteredConsumer> getConsumers() {
            return consumers;
        }

        void addConsumer(RegisteredConsumer consumer) {
            this.consumers.add(consumer);
        }

        void removeConsumer(EventConsumer consumer) {
            for (RegisteredConsumer cons : consumers) {
                if (cons.getConsumer().equals(consumer)) {
                    this.consumers.remove(cons);
                    return;
                }
            }
        }
    }
}
