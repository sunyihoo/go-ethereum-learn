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

package version

// 通过 Major（主版本）、 Minor（次版本）、 Patch（补丁版本）和 Meta（元数据）来标识软件的当前版本。
const (
	Major = 1          // Major version component of the current release 当前发布版本的主要版本组成部分
	Minor = 14         // Minor version component of the current release 当前发布版本的次要版本组成部分
	Patch = 13         // Patch version component of the current release 当前发布版本的补丁版本组成部分
	Meta  = "unstable" // Version metadata to append to the version string 附加到版本字符串的版本元数据
)

var gitCommit string = "9b68875d68b409eb2efdb68a4b623aaacc10a5b6"
