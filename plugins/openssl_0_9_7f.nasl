#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17754);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/22 19:25:29 $");

  script_cve_id("CVE-2004-0975");
  script_bugtraq_id(11293);
  script_osvdb_id(11125);

  script_name(english:"OpenSSL < 0.9.7f Insecure Temporary File Creation");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary files could be overwritten on the remote server.");

  script_set_attribute(attribute:"description", value:
"According to its banner, the remote server is running a version of 
OpenSSL that is earlier than 0.9.7f. 

The der_chop script that is shipped with these versions allows a
malicious user to overwrite arbitrary files. 

Note that this was fixed in the 0.9.6 CVS but no new version was
published in the 0.9.6 branch.");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html#2004-0975");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.7f or later.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/09/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/22");
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

openssl_check_version(fixed:'0.9.7f', severity:SECURITY_NOTE);
