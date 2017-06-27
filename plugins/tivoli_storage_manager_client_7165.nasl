#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100157);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/12 17:55:09 $");

  script_cve_id("CVE-2016-8916");
  script_bugtraq_id(98335);
  script_osvdb_id(156738);
  script_xref(name:"IAVB", value:"2017-B-0053");

  script_name(english:"IBM Spectrum Protect Client Instrumentation Log Credentials Disclosure");
  script_summary(english:"Checks the version of IBM Spectrum Protect Client.");

  script_set_attribute(attribute:"synopsis", value:
"A client application installed on the remote host is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Spectrum Protect Client installed on the remote
host is 5.5.x or 6.x prior to 6.4.3.5 or else 7.1.x prior to 7.1.6.5.
It is, therefore, affected by an information disclosure vulnerability
when using the 'set password' client command due to the full text of
the command and the included password being written to the
instrumentation log file. This issue occurs when instrumentation
tracing is enabled. A local attacker can exploit this vulnerability to
disclose credentials.

Note that for version 7.1.6.0 and higher, instrumentation tracing is
enabled by default, but it can be disabled by using the
'ENABLEINSTRUMENTATION NO' setting. Prior to 7.1.6.0, instrumentation
tracing was enabled by using the 'INSTRUMENT:*' testflag.

IBM Spectrum Protect was formerly known as IBM Tivoli Storage Manager
in releases prior to version 7.1.3.");
  script_set_attribute(attribute:"see_also", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21998166");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Spectrum Protect Client version 6.4.3.5 / 7.1.6.5 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager_client");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("tivoli_storage_manager_client_installed.nasl", "tivoli_storage_manager_client_installed_linux.nbin");
  script_require_keys("installed_sw/Tivoli Storage Manager Client");

  exit(0);
}

include("vcf.inc");

app = 'Tivoli Storage Manager Client';

win_local = FALSE;
if (get_kb_item("SMB/Registry/Enumerated")) win_local = TRUE;

app_info = vcf::get_app_info(app:app, win_local:win_local);

constraints = [
  { "min_version":"5.5", "max_version":"5.5.9999", "fixed_version":"7.1.6.5" },
  { "min_version":"6.1", "max_version":"6.3.9999", "fixed_version":"7.1.6.5" },
  { "min_version":"6.4", "max_version":"6.4.3.4", "fixed_version":"6.4.3.5" },
  { "min_version":"7.1", "max_version":"7.1.6.4", "fixed_version":"7.1.6.5"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
