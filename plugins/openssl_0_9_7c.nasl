#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17753);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/02/22 19:25:29 $");

  script_cve_id("CVE-2003-0543", "CVE-2003-0544", "CVE-2003-0545");
  script_bugtraq_id(8732);
  script_osvdb_id(3684, 3686, 3949);
  script_xref(name:"CERT-CC", value:"CA-2003-26");
  script_xref(name:"CERT", value:"255484");
  script_xref(name:"CERT", value:"380864");

  script_name(english:"OpenSSL < 0.9.7c ASN.1 Decoding Vulnerabilities");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:"Arbitrary code could be executed on the remote server.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote server is running a version of
OpenSSL that is earlier than 0.9.7c. 

A remote attacker could trigger a denial of service or even execute
arbitrary code by using an invalid client certificate.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21247112");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.7c or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2003/09/30");
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

openssl_check_version(fixed:'0.9.7c', min:'0.9.7', severity:SECURITY_HOLE);
