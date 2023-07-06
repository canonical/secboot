// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2023 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package efi_test

import (
	"errors"
	"io"
	"io/ioutil"
	"path/filepath"

	"github.com/snapcore/secboot"
	"github.com/snapcore/snapd/snap"
	. "gopkg.in/check.v1"

	. "github.com/snapcore/secboot/efi"
	"github.com/snapcore/secboot/internal/testutil"
)

type mockSnapImageReader struct{}

func (mockSnapImageReader) ReadAt(p []byte, off int64) (int, error) { return 0, nil }
func (mockSnapImageReader) Close() error                            { return nil }
func (mockSnapImageReader) Size() int64                             { return 0 }

type mockSnapContainer struct {
	r   mockSnapImageReader
	err error
}

func (*mockSnapContainer) Size() (int64, error) { return 0, nil }

func (c *mockSnapContainer) RandomAccessFile(relative string) (interface {
	io.ReaderAt
	io.Closer
	Size() int64
}, error) {
	if c.err != nil {
		return nil, c.err
	}
	return &c.r, nil
}

func (*mockSnapContainer) ReadFile(relative string) ([]byte, error)             { return nil, nil }
func (*mockSnapContainer) Walk(relative string, walkFn filepath.WalkFunc) error { return nil }
func (*mockSnapContainer) ListDir(path string) ([]string, error)                { return nil, nil }
func (*mockSnapContainer) Install(targetPath, mountDir string, opts *snap.InstallOptions) (bool, error) {
	return false, nil
}
func (*mockSnapContainer) Unpack(src, dst string) error { return nil }

type imageSuite struct{}

var _ = Suite(&imageSuite{})

func (s *imageSuite) TestNewSnapFileImage1(c *C) {
	container := new(mockSnapContainer)
	image := NewSnapFileImage(container, "foo")
	c.Check(image, DeepEquals, &SnapFileImage{Container: container, FileName: "foo"})
}

func (s *imageSuite) TestNewSnapFileImage2(c *C) {
	container := new(mockSnapContainer)
	image := NewSnapFileImage(container, "bar")
	c.Check(image, DeepEquals, &SnapFileImage{Container: container, FileName: "bar"})
}

func (s *imageSuite) TestSnapFileImageOpen(c *C) {
	container := new(mockSnapContainer)
	image := NewSnapFileImage(container, "foo")
	r, err := image.Open()
	c.Check(err, IsNil)
	c.Check(r, Equals, &container.r)
}

func (s *imageSuite) TestSnapFileImageOpenError(c *C) {
	container := &mockSnapContainer{err: errors.New("some error")}
	image := NewSnapFileImage(container, "foo")
	_, err := image.Open()
	c.Check(err, Equals, container.err)
}

func (s *imageSuite) TestNewFileImage1(c *C) {
	image := NewFileImage("/foo")
	c.Check(image, Equals, FileImage("/foo"))
}

func (s *imageSuite) TestNewFileImage2(c *C) {
	image := NewFileImage("/bar")
	c.Check(image, Equals, FileImage("/bar"))
}

func (s *imageSuite) TestFileImageOpen(c *C) {
	contents := []byte("some file contents")

	dir := c.MkDir()
	c.Check(ioutil.WriteFile(filepath.Join(dir, "foo"), contents, 0644), IsNil)

	image := NewFileImage(filepath.Join(dir, "foo"))
	r, err := image.Open()
	c.Assert(err, IsNil)
	defer r.Close()

	c.Check(r.Size(), Equals, int64(18))
	data, err := ioutil.ReadAll(io.NewSectionReader(r, 0, 1<<63-1))
	c.Check(data, DeepEquals, contents)
}

func (s *imageSuite) TestKernelCommandlineParams(c *C) {
	activity := NewImageLoadActivity(nil, KernelCommandlineParams(
		"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
		"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover"))
	params := ImageLoadActivityParams(activity).Resolve(new(LoadParams))
	c.Check(params, DeepEquals, []LoadParams{
		{KernelCommandline: "console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run"},
		{KernelCommandline: "console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover"}})
}

func (s *imageSuite) TestKernelCommandlineParamsInherited(c *C) {
	model := testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")

	activity := NewImageLoadActivity(nil, KernelCommandlineParams(
		"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover",
		"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run"))
	params := ImageLoadActivityParams(activity).Resolve(&LoadParams{SnapModel: model})
	c.Check(params, DeepEquals, []LoadParams{
		{KernelCommandline: "console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover", SnapModel: model},
		{KernelCommandline: "console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run", SnapModel: model}})
}

func (s *imageSuite) TestKernelCommandlineParamsOverride(c *C) {
	activity := NewImageLoadActivity(nil, KernelCommandlineParams(
		"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run"))
	params := ImageLoadActivityParams(activity).Resolve(&LoadParams{KernelCommandline: "foo"})
	c.Check(params, DeepEquals, []LoadParams{
		{KernelCommandline: "console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run"}})
}

func (s *imageSuite) TestSnapModelParams(c *C) {
	models := []secboot.SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "other-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}
	activity := NewImageLoadActivity(nil, SnapModelParams(models...))
	params := ImageLoadActivityParams(activity).Resolve(new(LoadParams))
	c.Check(params, DeepEquals, []LoadParams{{SnapModel: models[0]}, {SnapModel: models[1]}})
}

func (s *imageSuite) TestSnapModelParamsInherited(c *C) {
	models := []secboot.SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "other-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}
	activity := NewImageLoadActivity(nil, SnapModelParams(models...))
	params := ImageLoadActivityParams(activity).Resolve(&LoadParams{KernelCommandline: "foo"})
	c.Check(params, DeepEquals, []LoadParams{
		{KernelCommandline: "foo", SnapModel: models[0]},
		{KernelCommandline: "foo", SnapModel: models[1]}})
}

func (s *imageSuite) TestSnapModelParamsOverride(c *C) {
	model := testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
		"authority-id": "fake-brand",
		"series":       "16",
		"brand-id":     "fake-brand",
		"model":        "fake-model",
		"grade":        "secured",
	}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")
	activity := NewImageLoadActivity(nil, SnapModelParams(model))
	params := ImageLoadActivityParams(activity).Resolve(&LoadParams{
		SnapModel: testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "other-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")})
	c.Check(params, DeepEquals, []LoadParams{{SnapModel: model}})
}

func (s *imageSuite) TestImageLoadParamSetResolveMultiple(c *C) {
	models := []secboot.SnapModel{
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "fake-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij"),
		testutil.MakeMockCore20ModelAssertion(c, map[string]interface{}{
			"authority-id": "fake-brand",
			"series":       "16",
			"brand-id":     "fake-brand",
			"model":        "other-model",
			"grade":        "secured",
		}, "Jv8_JiHiIzJVcO9M55pPdqSDWUvuhfDIBJUS-3VW7F_idjix7Ffn5qMxB21ZQuij")}
	cmdlines := []string{
		"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
		"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover"}
	activity := NewImageLoadActivity(nil,
		KernelCommandlineParams(cmdlines...),
		SnapModelParams(models...))
	params := ImageLoadActivityParams(activity).Resolve(new(LoadParams))
	c.Check(params, DeepEquals, []LoadParams{
		{KernelCommandline: cmdlines[0], SnapModel: models[0]},
		{KernelCommandline: cmdlines[1], SnapModel: models[0]},
		{KernelCommandline: cmdlines[0], SnapModel: models[1]},
		{KernelCommandline: cmdlines[1], SnapModel: models[1]},
	})
}

func (s *imageSuite) TestImageLoadActivityLoads(c *C) {
	activities := []ImageLoadActivity{NewImageLoadActivity(nil), NewImageLoadActivity(nil)}
	activity := NewImageLoadActivity(nil)
	c.Check(activity.Loads(activities...), Equals, activity)
	c.Check(ImageLoadActivityNext(activity), DeepEquals, activities)
}

func (s *imageSuite) TestImageLoadSequencesAppend(c *C) {
	sequences := NewImageLoadSequences()

	activity1 := NewImageLoadActivity(nil)
	activity2 := NewImageLoadActivity(nil)
	c.Check(sequences.Append(activity1, activity2), Equals, sequences)
	c.Check(sequences.Images(), DeepEquals, []ImageLoadActivity{activity1, activity2})

	activity3 := NewImageLoadActivity(nil)
	c.Check(sequences.Append(activity3), Equals, sequences)
	c.Check(sequences.Images(), DeepEquals, []ImageLoadActivity{activity1, activity2, activity3})
}

func (s *imageSuite) TestImageLoadSequencesParams(c *C) {
	sequences := NewImageLoadSequences(KernelCommandlineParams(
		"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run",
		"console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover"))
	params := sequences.Params().Resolve(new(LoadParams))
	c.Check(params, DeepEquals, []LoadParams{
		{KernelCommandline: "console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=run"},
		{KernelCommandline: "console=ttyS0 console=tty1 panic=-1 systemd.gpt_auto=0 snapd_recovery_mode=recover"}})
}
