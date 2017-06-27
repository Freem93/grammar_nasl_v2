#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22311);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/05/02 23:36:52 $");

  script_cve_id("CVE-2006-2073", "CVE-2006-4095", "CVE-2006-4096");
  script_bugtraq_id(19859);
  script_osvdb_id(28557, 28558, 57060);

  script_name(english:"ISC BIND 9 Multiple Remote DoS");
  script_summary(english:"Checks version of BIND");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server may be affected by multiple denial of service
vulnerabilities." );
  script_set_attribute(attribute:"description", value:
"The version of BIND installed on the remote host suggests that it
suffers from multiple denial of service vulnerabilities that could be
triggered by either by sending a large volume of recursive queries or
queries for SIG records where there are multiple SIG(covered) RRsets. 

Note that Nessus obtained the version by sending a special DNS request
for the text 'version.bind' in the domain 'chaos', the value of which
can be and sometimes is tweaked by DNS administrators." );
  # http://web.archive.org/web/20071107080553/https://www.cpni.gov.uk/Docs/re-20060905-00590.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16b13df1" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND 9.4.0b2 / 9.3.3rc2 / 9.3.2-P1 / 9.2.7rc2 / 9.2.6-P1 or
later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"plugin_publication_date", value: "2006/09/07");
  script_set_attribute(attribute:"vuln_publication_date", value: "2006/09/06");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english: "DNS");

  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version");

  exit(0);
}


include("global_settings.inc");


# Banner checks of BIND are prone to false-positives so we only
# run the check if reporting is paranoid.
if (report_paranoia <= 1) exit(0);


ver = get_kb_item("bind/version");
if (!ver) exit(0);

if (ver =~ "^9\.(2\.([0-5][^0-9]?|6(b|rc|$)|7(b|rc1))|3\.([01][^0-9]?|2(b|rc|$)|3(b|rc1))|4\.0b1)")
  security_warning(53);
