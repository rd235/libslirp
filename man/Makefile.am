man_MANS = libslirp.3

install-data-hook:
	ln -sf libslirp.3 $(DESTDIR)$(man3dir)/slirp_open.3
	ln -sf libslirp.3 $(DESTDIR)$(man3dir)/slirp_start.3
	ln -sf libslirp.3 $(DESTDIR)$(man3dir)/slirp_send.3
	ln -sf libslirp.3 $(DESTDIR)$(man3dir)/slirp_recv.3
	ln -sf libslirp.3 $(DESTDIR)$(man3dir)/slirp_fd.3
	ln -sf libslirp.3 $(DESTDIR)$(man3dir)/slirp_close.3

uninstall-hook:
	rm -f $(DESTDIR)$(man3dir)/slirp_open.3
	rm -f $(DESTDIR)$(man3dir)/slirp_start.3
	rm -f $(DESTDIR)$(man3dir)/slirp_send.3
	rm -f $(DESTDIR)$(man3dir)/slirp_recv.3
	rm -f $(DESTDIR)$(man3dir)/slirp_fd.3
	rm -f $(DESTDIR)$(man3dir)/slirp_close.3
