#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(73670);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id("CVE-2014-0076", "CVE-2014-0160");
  script_bugtraq_id(66363, 66690);
  script_osvdb_id(104810, 105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");
  script_xref(name:"VMSA", value:"2014-0004");

  script_name(english:"VMware Fusion 6.x < 6.0.3 OpenSSL Library Multiple Vulnerabilities (VMSA-2014-0004) (Heartbleed)");
  script_summary(english:"Checks version of Fusion");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware Fusion 6.x installed on the remote Mac OS X host
is prior to 6.0.3.  It is, therefore, reportedly affected by the
following vulnerabilities in the OpenSSL library :

  - An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    could allow nonce disclosure via the 'FLUSH+RELOAD'
    cache side-channel attack. (CVE-2014-0076)

  - An out-of-bounds read error, known as the 'Heartbleed
    Bug', exists related to handling TLS heartbeat
    extensions that could allow an attacker to obtain
    sensitive information such as primary key material,
    secondary key material and other protected content.
    (CVE-2014-0160)");

  script_set_attribute(attribute:"solution", value:"Upgrade to VMware Fusion 6.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2076225");
  # https://www.vmware.com/support/fusion6/doc/fusion-603-release-notes.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd08e50e");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:fusion");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_fusion_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "MacOSX/Fusion/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("Host/local_checks_enabled");

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

version = get_kb_item_or_exit("MacOSX/Fusion/Version");
path = get_kb_item_or_exit("MacOSX/Fusion/Path");

fixed_version = '6.0.3';
if (
  version =~ "^6\." &&
  ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "VMware Fusion", version, path);
