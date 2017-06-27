#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74124);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/04/21 16:17:30 $");

  script_cve_id("CVE-2013-4164");
  script_bugtraq_id(63873);
  script_osvdb_id(100113);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-15-20-1");

  script_name(english:"Mac OS X : OS X Server < 3.1.2 Heap-Based Buffer Overflow");
  script_summary(english:"Checks OS X Server version");

  script_set_attribute(attribute:"synopsis", value:"The remote host is missing a security update for OS X Server.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.9 host has a version of OS X Server installed
that is prior to 3.1.2. It is, therefore, affected by a heap-based
buffer overflow vulnerability in the Ruby component that occurs when
converting a string to a floating point value. A remote attacker can
exploit this, via a specially crafted request to Profile Manager or to
a Ruby script, to cause a denial of service condition or the execution
of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6248");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/532166/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Mac OS X Server version 3.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:mac_os_x_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_server_services.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Server/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

if (!ereg(pattern:"Mac OS X 10\.9([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.9");

version = get_kb_item_or_exit("MacOSX/Server/Version");

fixed_version = "3.1.2";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_warning(port:0, extra:report);
  }
  else security_warning(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "OS X Server", version);
