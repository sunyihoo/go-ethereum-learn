// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package event

import "sync"

// Subscription represents a stream of events. The carrier of the events is typically a
// channel, but isn't part of the interface.
//
// Subscriptions can fail while established. Failures are reported through an error
// channel. It receives a value if there is an issue with the subscription (e.g. the
// network connection delivering the events has been closed). Only one value will ever be
// sent.
//
// The error channel is closed when the subscription ends successfully (i.e. when the
// source of events is closed). It is also closed when Unsubscribe is called.
//
// The Unsubscribe method cancels the sending of events. You must call Unsubscribe in all
// cases to ensure that resources related to the subscription are released. It can be
// called any number of times.
type Subscription interface {
	Err() <-chan error // returns the error channel
	Unsubscribe()      // cancels sending of events, closing the error channel
}

// NewSubscription runs a producer function as a subscription in a new goroutine. The
// channel given to the producer is closed when Unsubscribe is called. If fn returns an
// error, it is sent on the subscription's error channel.
func NewSubscription(producer func(<-chan struct{}) error) Subscription {
	s := &funcSub{unsub: make(chan struct{}), err: make(chan error, 1)}
	go func() {
		defer close(s.err)
		err := producer(s.unsub)
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.unsubscribed {
			if err != nil {
				s.err <- err
			}
			s.unsubscribed = true
		}
	}()
	return s
}

type funcSub struct {
	unsub        chan struct{}
	err          chan error
	mu           sync.Mutex
	unsubscribed bool
}

func (s *funcSub) Unsubscribe() {
	s.mu.Lock()
	if s.unsubscribed {
		s.mu.Unlock()
		return
	}
	s.unsubscribed = true
	close(s.unsub)
	s.mu.Unlock()
	// Wait for producer shutdown.
	<-s.err
}

func (s *funcSub) Err() <-chan error {
	return s.err
}

// SubscriptionScope provides a facility to unsubscribe multiple subscriptions at once.
//
// For code that handle more than one subscription, a scope can be used to conveniently
// unsubscribe all of them with a single call. The example demonstrates a typical use in a
// larger program.
//
// The zero value is ready to use.
type SubscriptionScope struct {
	mu     sync.Mutex
	subs   map[*scopeSub]struct{}
	closed bool
}

type scopeSub struct {
	sc *SubscriptionScope
	s  Subscription
}

// Track starts tracking a subscription. If the scope is closed, Track returns nil. The
// returned subscription is a wrapper. Unsubscribing the wrapper removes it from the
// scope.
func (sc *SubscriptionScope) Track(s Subscription) Subscription {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.closed {
		return nil
	}
	if sc.subs == nil {
		sc.subs = make(map[*scopeSub]struct{})
	}
	ss := &scopeSub{sc, s}
	sc.subs[ss] = struct{}{}
	return ss
}

// Count returns the number of tracked subscriptions.
// It is meant to be used for debugging.
func (sc *SubscriptionScope) Count() int {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return len(sc.subs)
}

func (s *scopeSub) Unsubscribe() {
	s.s.Unsubscribe()
	s.sc.mu.Lock()
	defer s.sc.mu.Unlock()
	delete(s.sc.subs, s)
}

func (s *scopeSub) Err() <-chan error {
	return s.s.Err()
}
