#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17759);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/22 19:25:29 $");

  script_cve_id("CVE-2005-2946");
  script_osvdb_id(19660);

  script_name(english:"OpenSSL < 0.9.8 Weak Default Configuration");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"The default configuration of OpenSSL on the remote server uses a weak
hash algorithm.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the remote server is running a version of 
OpenSSL that is earlier than 0.9.8. 

The default configuration uses MD5 instead of a stronger hash
algorithm.  An attacker could forge certificates. 

If you never generate certificates on this machine, you may ignore
this warning.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.launchpad.net/ubuntu/+source/openssl/+bug/19835");
  script_set_attribute(attribute:"see_also", value:"http://www.ubuntu.com/usn/usn-179-1/");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenSSL 0.9.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/05");
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

openssl_check_version(fixed:'0.9.8', severity:SECURITY_WARNING);
