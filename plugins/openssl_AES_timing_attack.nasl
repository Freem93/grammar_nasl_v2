#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17769);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/01/05 11:58:59 $");

  script_cve_id("CVE-2005-1797");
  script_bugtraq_id(13785);
  script_osvdb_id(20501);

  script_name(english:"OpenSSL AES Timing Attack"); 
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by a timing attack.");
  script_set_attribute(attribute:"description", value:
"S-box lookup can hardly be performed in constant time in AES
implementations.  Theoretically, remote attackers could recover AES
keys by performing a timing attack on these S-box lookup.  No
practical implementation of a remote attack is known.");
  script_set_attribute(attribute:"see_also", value:"http://cr.yp.to/antiforgery/cachetiming-20050414.pdf");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("Settings/ParanoidReport", "openssl/port", "Settings/PCI_DSS");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item_or_exit("openssl/port");

if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");
security_warning(port);
