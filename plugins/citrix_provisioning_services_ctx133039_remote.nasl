#TRUSTED 19d507a42667c31b9345f9d6f7f5cd7edd6a31ce0c5ab95281a78fbc1be44948a5989d09a22baafb8e0da167369fc33bed2072a044b6ff82ab94f27f84b9538a4ae15ef26294d856c1fc34450451320caa8674fa8663a32c04c49a7991c1a5cacc623c7f40c83f5cb202767e14f84a63d9b87ae1d759432bfd43519dc0386297caae94b844d4b20dafb683b509d4c3cfbf4f8f6053a53e1b934982c050eaf3d0dff917c3c93470262b3a4cdcf7e2d8164b953d278a6e353cd9cf119cc14007ee94d9b7242577fa2d3a8425a1261fe01251dc134ad58352bb67aa068172c91279d99441b9332b8040a2b55e81c4b187f42ff7a98863b5b201c33de5b0a6ec15ed6e84a9f951605f388341403fcda126292eea3799247d7d06f34307fa36dc0adb0131bae10b524bc0bd76cef552a335f645d4ffad02673147e4e3fd1c88901ee74c3ffb8eab1d49aeb50c5c3f63e5757cc6be1403201eff0f673b9a98f10c96fd2f57ada4ed82e6ec07ec0e5dd7b04460d2a3558cd32deb5b2f113e22380d6c10ae382bda33da22ccc6c322ecf04ffe00ef6dc7098ef67a180efe157bc8e3ec664bc7626de39dc5851b8b4481dc0ef935fc89af4a14000385e3131635c30c3c139bce67ca5bfe0d1828f678e3af8543067eeecf9a5ee733e46085b3a1fb0b065faa7fe0db48f73ccbc75ff44bb8a88ea010b47629be53a46617672a5222e894ba
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (!defined_func("recvfrom") || !defined_func("sendto")) exit(1, "recvfrom() / sendto() not defined.");

if (description)
{
  script_id(59465);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/02/03");

  script_cve_id("CVE-2012-4068");
  script_bugtraq_id(53330);
  script_osvdb_id(81664);

  script_name(english:"Citrix Provisioning Services Unspecified Request Parsing Remote Code Execution (CTX133039) (uncredentialed check)");
  script_summary(english:"Checks version in bootstrap file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application running that is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Provisioning Services running on the remote
Windows host is affected by a remote code execution vulnerability in
the SoapServer service due to improper validation of user-supplied
input when parsing date and time strings. An unauthenticated, remote
attacker can exploit this to cause a buffer overflow, resulting in a
denial of service condition or the execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX133039");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch from the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:provisioning_services");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("tftpd_detect.nasl");
  script_require_udp_ports(69, 6969);

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("byte_func.inc");
include("misc_func.inc");
include("tftp_func.inc");

function ctxpvs_two_stage_get(port, path)
{
  local_var s, sport, file, response, id, data, dport, rlen, i, src_ip, num_chunks;

  file = "";
  rlen = NULL;

  if (isnull(port)) port = 6969;

  if (known_service(port:port, ipproto:"udp")) return NULL;
  if (!get_udp_port_state(port)) return NULL;

  s = bind_sock_udp();
  if (!s) audit(AUDIT_SOCK_FAIL, 'udp', 'unknown');

  sport = s[1];
  s = s[0];

  sendto(socket:s, data:'\x08\x17' + path + '\x00', dst:get_host_ip(), port:port);

  num_chunks = 0;
  while (TRUE)
  {
    response = recvfrom(socket:s, port:sport, src:get_host_ip());
    if (!response)
    {
      file = "";
      break;
    }
    dport = response[2];
    src_ip = response[1];
    response = response[0];
    if (src_ip != get_host_ip() || strlen(response) < 5 || substr(response, 0, 1) != '\x08\x97')
    {
      file = "";
      break;
    }
    id = substr(response, 2, 3);
    data = substr(response, 4);
    if (isnull(rlen)) rlen = strlen(data);

    sendto(socket:s, data:'\x08\xD7' + id, dst:get_host_ip(), port:dport);

    file += data;
    num_chunks++;

    # Allow up to 200 chunks to be received.
    if(strlen(data) != rlen || num_chunks > 200) break;
  }
  if (strlen(file) == 0)
  {
    return NULL;
  }
  else
  {
    for(i = 0; i < strlen(file); i++)
    {
      # Returned file needs XORed by 0xFF to decode.
      file[i] = mkbyte(getbyte(blob:file, pos:i) ^ 0xFF);
    }
    register_service(port:port, ipproto:"udp", proto:"citrix_two_stage_bootsrv");
    return file;
  }
}

function ctxpvs_version()
{
  local_var version_string, loc, version, i, file;

  file = _FCT_ANON_ARGS[0];

  version_string = "Provisioning Services bootstrap v";

  loc = stridx(file, version_string);

  if (loc == -1)
  {
    return NULL;
  }

  loc += strlen(version_string); # skip to version number
  version = "";
  for (i = loc; i < strlen(file); i++)
  {
    if (ord(file[i]) == 0x00) break;
    version += file[i];
  }

  if(strlen(version) == 0)
  {
    return NULL;
  }

  version = chomp(version);
  if (version =~ "^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}$")
  {
    return version;
  }
  else
  {
    return NULL;
  }
}

if ( TARGET_IS_IPV6 ) exit(1, "IPv6 not supported");

file = NULL;
version = NULL;

file = ctxpvs_two_stage_get(path:'tsbbdm.bin');
if (!isnull(file))
{
  version = ctxpvs_version(file);
}

# If we couldn't retrieve a bootstrap file through the two-stage
# boot service  or determine version from it then try tftp.
if (isnull(file) || isnull(version))
{
  port = get_service(svc:'tftp', ipproto:"udp", exit_on_fail:TRUE);

  # Citrix tftp doesn't obey block size and always uses 512.
  # Override 1024 used in tftp_func.inc to make Citrix happy.
  TFTP_BLOCK_SIZE = 512;

  file = tftp_get(port:port, path:'ARDBP32.BIN');

  if (isnull(file)) exit(0, "The version of Citrix Provisioning Services could not be determined.");
  version = ctxpvs_version(file);
}

if (isnull(version)) audit(AUDIT_VER_FAIL, 'the bootstrap file');

fix = NULL;

v = split(version, sep:'.', keep:FALSE);

for (i=0; i < max_index(v); i++)
  v[i] = int(v[i]);

if (v[0] < 5 || (v[0] == 5 && v[1] < 6)) fix = '6.1.0.1082';
if (version =~ '^5\\.6\\.' && ver_compare(ver:version, fix:'5.6.3.1349') == -1) fix = '5.6.3.1349';
else if (version =~ '^6\\.0\\.0' && ver_compare(ver:version, fix:'6.0.0.1083') == -1) fix = '6.0.0.1083';
else if (version =~ '^6\\.1\\.0' && ver_compare(ver:version, fix:'6.1.0.1082') == -1) fix = '6.1.0.1082';

if (!isnull(fix))
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:54321, extra:report);
  }
  else security_hole(port:54321);
  exit(0);
}
audit(AUDIT_INST_VER_NOT_VULN, 'Citrix Provisioning Services', version);
