#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17775);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/11 19:30:34 $");

  script_cve_id("CVE-2007-5549");
  script_osvdb_id(45363);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsk16129");

  script_name(english:"Cisco IOS Command EXEC Unspecified Vulnerability");
  script_summary(english:"Checks IOS version");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"An unspecified vulnerability in Command EXEC allows local users to
bypass command restrictions and obtain sensitive information via an
unspecified 'variation of an IOS command'.");
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Settings/PCI_DSS");

  exit(0);
}

include("cisco_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Only PCI considers this an issue.
if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

if (deprecated_version(version, "12.4M"))
{
  security_note(port:0, extra:version);
  exit(0);
}

exit(0, "The host is not affected.");
