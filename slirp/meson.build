project('slirp', 'c',
        version : '4.0.0',
        license : 'BSD-3-Clause',
        default_options : ['warning_level=1', 'c_std=gnu99']
       )

version = meson.project_version()
varr = version.split('.')
major_version = varr[0]
minor_version = varr[1]
micro_version = varr[2]

conf = configuration_data()
conf.set('SLIRP_MAJOR_VERSION', major_version)
conf.set('SLIRP_MINOR_VERSION', minor_version)
conf.set('SLIRP_MICRO_VERSION', micro_version)

# libtool versioning - this applies to libpackagekit
#
# See http://sources.redhat.com/autobook/autobook/autobook_91.html#SEC91 for details
#
# - If interfaces have been changed or added, but binary compatibility
#   has been preserved, change:
#      CURRENT += 1
#      REVISION = 0
#      AGE += 1
# - If binary compatibility has been broken (eg removed or changed
#   interfaces), change:
#      CURRENT += 1
#      REVISION = 0
#      AGE = 0
# - If the interface is the same as the previous version, but bugs are
#   fixed, change:
#      REVISION += 1
lt_current = '0'
lt_revision = '0'
lt_age = '0'
lt_version = '@0@.@1@.@2@'.format(lt_current, lt_age, lt_revision)

host_system = host_machine.system()

glib_dep = dependency('glib-2.0')

cc = meson.get_compiler('c')

platform_deps = []

if host_system == 'windows'
  platform_deps += [
    cc.find_library('ws2_32'),
    cc.find_library('iphlpapi')
  ]
endif

cargs = [
  '-DG_LOG_DOMAIN="Slirp"',
]

sources = [
  'arp_table.c',
  'bootp.c',
  'cksum.c',
  'dhcpv6.c',
  'dnssearch.c',
  'if.c',
  'ip6_icmp.c',
  'ip6_input.c',
  'ip6_output.c',
  'ip_icmp.c',
  'ip_input.c',
  'ip_output.c',
  'mbuf.c',
  'misc.c',
  'ncsi.c',
  'ndp_table.c',
  'sbuf.c',
  'slirp.c',
  'socket.c',
  'state.c',
  'stream.c',
  'tcp_input.c',
  'tcp_output.c',
  'tcp_subr.c',
  'tcp_timer.c',
  'tftp.c',
  'udp.c',
  'udp6.c',
  'util.c',
  'version.c',
  'vmstate.c',
]

mapfile = 'libslirp.map'
vflag = '-Wl,--version-script,@0@/@1@'.format(meson.current_source_dir(), mapfile)

lib = shared_library('slirp', sources,
                     soversion : lt_current,
                     version : lt_version,
                     c_args : cargs,
                     link_args : vflag,
                     link_depends : mapfile,
                     dependencies : [glib_dep, platform_deps],
                     install : true)

configure_file(
  input : 'libslirp-version.h.in',
  output : 'libslirp-version.h',
  install_dir : join_paths(get_option('includedir'), 'slirp'),
  configuration : conf
)

install_headers(['libslirp.h'], subdir : 'slirp')

pkg = import('pkgconfig')

pkg.generate(
  version : version,
  libraries : lib,
  requires : [
    'glib-2.0',
  ],
  name : 'slirp',
  description : 'User-space network stack',
  filebase : 'slirp',
  subdirs : 'slirp',
)
