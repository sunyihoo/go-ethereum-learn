package ethdb

import (
	"errors"
	"testing"
)

type mockIterator struct {
	keys   [][]byte
	values [][]byte
	pos    int
	err    error
}

func (m *mockIterator) Next() bool {
	if m.err != nil || m.pos >= len(m.keys) {
		return false
	}
	m.pos++
	return m.pos <= len(m.keys)
}

func (m *mockIterator) Error() error {
	return m.err
}

func (m *mockIterator) Key() []byte {
	if m.pos == 0 || m.pos > len(m.keys) {
		return nil
	}
	return m.keys[m.pos-1]
}

func (m *mockIterator) Value() []byte {
	if m.pos == 0 || m.pos > len(m.values) {
		return nil
	}
	return m.values[m.pos-1]
}

func (m *mockIterator) Release() {}

func TestIterator(t *testing.T) {
	// 测试用例 1：正常迭代
	it := &mockIterator{
		keys:   [][]byte{{1}, {2}, {3}},
		values: [][]byte{{4}, {5}, {6}},
	}
	if !it.Next() || string(it.Key()) != "\x01" || string(it.Value()) != "\x04" {
		t.Errorf("Expected first pair (1, 4), got (%v, %v)", it.Key(), it.Value())
	}
	if !it.Next() || string(it.Key()) != "\x02" || string(it.Value()) != "\x05" {
		t.Errorf("Expected second pair (2, 5), got (%v, %v)", it.Key(), it.Value())
	}
	if !it.Next() || string(it.Key()) != "\x03" || string(it.Value()) != "\x06" {
		t.Errorf("Expected third pair (3, 6), got (%v, %v)", it.Key(), it.Value())
	}
	if it.Next() {
		t.Errorf("Expected exhaustion after third pair")
	}

	// 测试用例 2：错误情况
	it = &mockIterator{
		keys:   [][]byte{{1}},
		values: [][]byte{{2}},
		err:    errors.New("test error"),
	}
	if it.Next() {
		t.Errorf("Expected no iteration on error")
	}
	if it.Error() == nil || it.Error().Error() != "test error" {
		t.Errorf("Expected error 'test error', got %v", it.Error())
	}

	// 测试用例 3：空迭代器
	it = &mockIterator{}
	if it.Next() {
		t.Errorf("Expected no iteration on empty iterator")
	}
	if it.Key() != nil || it.Value() != nil {
		t.Errorf("Expected nil key and value on empty iterator")
	}
}
