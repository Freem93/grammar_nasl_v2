#TRUSTED 1eebde48b1f7b09f529b97158721268b2925a124043051ab424f48f6eb34e66701a2cc4f4296b48785fce2a4f64df71d3aff7e2cae3aa4cb01118b6b1b655bbe18a09bfbab4575abbe74dd5b8d57484bd38d0d22a73b95f157824102a6bec4843459f77e57f637af8f4a0f98c0918b7c5520ac7b37960b35fde1a7496b36ef868162c9eea5759a7781f49dd35a5cd53c06f2fee6b479cb4e395e0dcf8f2bfc96858a5d0ecee1bd6df0109999816395020752af2bd26c71d973902b318cd81380bd0b1bcd9f50265f10ccfc02a4f5854149dc27be1a32378228ec5ee4e00862f7b224d21cd6691d7d4d952ca6d4b31cd813e6efc44c3ef872e2766fe4c51655a315655c605d48bfc6fefc64f806a3baf286798a556d421f99706040b2d15a4be3b69e6d2c4d6827cda65bffa3a9502b82e4528579ef9fb3192ed9d3af9cb3fa58f763898200fdc8bd7a4c7fe9ac2d84f62a0a012ad4e7820a41f092b500311b0ce7cf18401b56676bce3d3d380dc209609815a43025a682ad18a4755649f04178d7460e797e9080b8ee3bd31be70e935c0578fb6e04d773a274ee54ae373cde207a6effe829355303c7b1e0b278dc6e4a530a3cd64aaf708286ac2e01b54a30cd0702e2665e3a753522928eea688d42cbb966f29fe3ec2677c3cafd77f8095153a9841baf0df074f26454281b3fa55f5939509ff63b6957d726fe3c08027589c5
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(47682);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value: "2017/05/16");

  script_cve_id("CVE-2010-2309");
  script_bugtraq_id(40489);
  script_osvdb_id(65043);
  script_xref(name:"EDB-ID", value:"13735");

  script_name(english:"EvoCam 3.6.6 / 3.6.7 Web Server GET Request Overflow");
  script_summary(english:"Checks version of EvoCam");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application that may be susceptible to a remote
buffer overflow attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of EvoCam installed on the Mac OS X host is either 3.6.6
or 3.6.7.  Such versions reportedly contain a buffer overflow in the
Web Server component. 

Using an overly long GET request, an unauthenticated remote attacker
may be able to leverage this vulnerability to execute arbitrary code
on the remote host subject to the privileges under which the
application runs."
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to EvoCam 3.6.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MacOS X EvoCam HTTP GET Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "http_version.nasl");
  script_require_keys("Host/MacOSX/packages");
  script_require_ports("Services/www", 8080, "Settings/ParanoidReport");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");


# Unless we're paranoid, make sure the service is enabled.
if (get_kb_item("global_settings/report_paranoia") != 'Paranoid')
{
  found = FALSE;
  ports = add_port_in_list(list:get_kb_list("Services/www"), port:8080);

  foreach port (ports)
  {
     soc = open_sock_tcp(port);
     if (soc)
     {
      send(socket:soc, data:http_get(item:"/", port:80));
      res = recv(socket:soc, length:1024);

      if (
        strlen(res) &&
        (
          "<title>EvoCam</title>" >< res ||
          '<applet archive="evocam.jar" code="com.evological.evocam.class"' >< res
        )
      ) found = TRUE;
      close(soc);
    }
    if (found) break;            
  } 
  if(!found) exit(0, "The EvoCam web server is not listening on the remote host.");
}


function exec(cmd)
{
  local_var ret, buf;

  if (islocalhost())
    buf = pread(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = ssh_open_connection();
    if (!ret) exit(1, "ssh_open_connection() failed.");
    buf = ssh_cmd(cmd:cmd);
    ssh_close_connection();
  }
  if (buf !~ "^[0-9]") exit(1, "Failed to get the version - '"+buf+"'.");

  buf = chomp(buf);
  return buf;
}


plist = "/Applications/EvoCam.app/Contents/Info.plist";
cmd = string(
  "cat '", plist, "' | ",
  "grep -A 1 CFBundleShortVersionString | ",
  "tail -n 1 | ",
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
);
version = exec(cmd:cmd);
if (!strlen(version)) exit(1, "Can't get version info from '"+plist+"'.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] == 3 && 
  ver[1] == 6 && 
  (ver[2] == 6 || ver[2] == 7)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report = 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.6.8\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since EvoCam "+version+" is installed.");
