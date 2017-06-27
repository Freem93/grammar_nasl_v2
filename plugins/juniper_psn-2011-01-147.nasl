#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55941);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_name(english:"Juniper Junos J-Web Weak SSL Ciphers (PSN-2011-01-147)");
  script_summary(english:"Checks model & version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The web interface on the remote router supports the use of
weak SSL ciphers."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the remote Junos device
contains a J-Web component that supports the use of weak SSL ciphers
(less than 128-bit).

Note: This is considerably easier to exploit if the attacker is on the
same physical network."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cb00ac84");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant Junos upgrade referenced in Juniper advisory
PSN-2011-01-147."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:P/I:N/A:N");
;  # same as ssl_weak_supported_ciphers.nasl
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/22");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("misc_func.inc");
include("junos.inc");

fixes['9.3'] = '9.3S16.1';
fixes['10.0'] = '10.0S10.1';
fixes['10.1'] = '10.1R4';
fixes['10.2'] = '10.2R3';
fixes['10.3'] = '10.3R2';
fixes['10.4'] = '10.4R1';

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

check_model(model:model, flags:SRX_SERIES | MX_SERIES | EX_SERIES | J_SERIES | T_SERIES | M_SERIES, exit_on_fail:TRUE);
fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  report = get_report(ver:ver, fix:fix, model:model);
  security_note(port:0, extra:report);
}
else security_note(0);

