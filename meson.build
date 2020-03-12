project('qtv', 'c')

qtv_sources = [
	'ban.c',
	'build.c',
	'cl_cmds.c',
	'cmd.c',
	'crc.c',
	'cvar.c',
	'forward.c',
	'forward_pending.c',
	'fs.c',
	'httpsv.c',
	'httpsv_generate.c',
	'info.c',
	'main.c',
	'mdfour.c',
	'msg.c',
	'net_utils.c',
	'parse.c',
	'qw.c',
	'source.c',
	'source_cmds.c',
	'sys.c',
	'token.c',
	'udp.c'
]

c_args = []

library('qtv', qtv_sources,
	include_directories : include_directories('.'),
	c_args : c_args,
	dependencies : [
		meson.get_compiler('c').find_library('m', required : false)
	],
	name_prefix : ''
)

