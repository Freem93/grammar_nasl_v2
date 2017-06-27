#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63113);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/12/02 00:40:05 $");

  script_cve_id("CVE-2012-4897");
  script_bugtraq_id(55802);
  script_osvdb_id(85957);
  script_xref(name:"VMSA", value:"2012-0014");

  script_name(english:"VMware Movie Decoder < 9.0 Path Subversion Arbitrary DLL Injection Code Execution (VMSA-2012-0014)");
  script_summary(english:"Checks file version of vmnc.dll");

  script_set_attribute(attribute:"synopsis", value:
"The movie decoder installed on the remote Windows host is affected by a
DLL loading vulnerability.");
  script_set_attribute( attribute:"description", value:
"The version of VMware Movie Decoder installed on the remote host is
earlier than 9.0 and is, therefore, affected by a DLL loading
vulnerability. 

This issue potentially allows for a local attacker to execute custom
code by writing a malicious executable into the same directory as the
VMware Movie Installer.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2012-0014.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.vmware.com/pipermail/security-announce/2012/000192.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Movie Decoder 9.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:movie_decoder");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("vmware_movie_decoder_detect.nasl");
  script_require_keys("SMB/VMware Movie Decoder/Installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

file = get_kb_item_or_exit("SMB/VMware Movie Decoder/File");
version = get_kb_item_or_exit("SMB/VMware Movie Decoder/Version");

fixed_version = '9.0';
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) < 0)
{
  port = get_kb_item('SMB/transport');

  if (report_verbosity > 0)
  {
    report +=
      '\n  File              : ' + file +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port:port);
} 
else audit(AUDIT_INST_PATH_NOT_VULN, "VMware Movie Decoder", version, file);
