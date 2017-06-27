#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17752);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/02/22 19:25:29 $");

  script_cve_id("CVE-2002-0657");
  script_bugtraq_id(5361);
  script_osvdb_id(3942);
  script_xref(name:"CERT-CC", value:"CA-2002-23");
  script_xref(name:"CERT", value:"561275");

  script_name(english:"OpenSSL < 0.9.7-beta3 Buffer Overflow");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by an arbitrary code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote server is running a version of 
OpenSSL that is earlier than 0.9.7-beta3. 

If Kerberos is enabled, a remote attacker could trigger a buffer
overflow with a long master key and execute arbitrary code.");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2002/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/12/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

if (get_kb_item("Settings/PCI_DSS"))
  openssl_check_version(fixed:'0.9.7', severity:SECURITY_HOLE);
else
  openssl_check_version(fixed:'0.9.7-beta3', severity:SECURITY_HOLE);
