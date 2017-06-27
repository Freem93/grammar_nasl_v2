#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65632);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/09/24 21:17:13 $");

  script_name(english:"Unsupported Novell NetWare Operating System");
  script_summary(english:"Checks if version of NetWare is out of support");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running an obsolete operating system.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Novell NetWare install on the remote
host is no longer supported by its vendor.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/lifecycle/");
  script_set_attribute(attribute:"solution", value:"Upgrade to a supported version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:netware");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Netware");

  script_dependencies("os_fingerprint.nasl");
  script_require_keys("Host/OS");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


oses = get_kb_item_or_exit("Host/OS");
if ("Novell NetWare" >!< oses) audit(AUDIT_OS_NOT, "Novell NetWare");

conf = get_kb_item_or_exit("Host/OS/Confidence");
if (conf <= 70) exit(0, "Can't determine the host's OS with sufficient confidence.");


dates = make_array(
  "Novell NetWare 6.5 SP7", "",
  "Novell NetWare 6.5 SP6", "",
  "Novell NetWare 6.5 SP5", "",
  "Novell NetWare 6.5 SP4", "",
  "Novell NetWare 6.5 SP3", "",
  "Novell NetWare 6.5 SP2", "",
  "Novell NetWare 6.5 SP1", "",
  "Novell NetWare 6.0",     "2006-11-01",       # end of Extended Support
  "Novell NetWare 5.1",     "2006-11-01",       # end of Extended Support
  "Novell NetWare 5",       "2002-03-31",       # end of General Support / Extended Support not offered
  "Novell NetWare 4.2",     "2004-06-01"        # end of General Support / Extended Support not offered
);
latest = "Novell NetWare 6.5 SP8";


all_oses = split(oses, keep:FALSE);
unsupported_oses = make_array();

foreach os (all_oses)
{
  matched = FALSE;
  foreach k (sort(keys(dates)))
  {
    if (k >< os)
    {
      match = eregmatch(pattern:"Novell NetWare ([0-9.]+)( (SP[0-9]))?", string:os);
      if (!isnull(match))
      {
        tmp_ver = match[1];
        if (match[3]) tmp_ver += ":" + tolower(match[3]);
        register_unsupported_product(product_name:"Novell NetWare", cpe_class:CPE_CLASS_OS,
                                     cpe_base:"novell:netware", version:tmp_ver);
      }
      else
      {
        register_unsupported_product(product_name:"Novell NetWare", cpe_class:CPE_CLASS_OS,
                                     cpe_base:"novell:netware");
      }

      unsupported_oses[os] = dates[k];
      matched = TRUE;
      break;
    }
  }

  # Unless we're paranoid, exit if the OS is *not* listed as out of
  # support; this includes an OS other than NetWare.
  if (!matched && report_paranoia < 2)
  {
    if (max_index(all_oses) > 1) exit(0, "Although it was not fingerprinted uniquely, the host may be running "+os+".");
    # otherwise, drop through and exit since there's only one OS.
  }
}
if (max_index(keys(unsupported_oses)) == 0) exit(0, "The host's OS is still supported since it has been fingerprinted as "+join(all_oses, sep:" / ")+".");

if (report_verbosity > 0)
{
  sep = " / ";
  unsupported_os_str = "";
  eos_date_str = "";
  foreach os (sort(keys(unsupported_oses)))
  {
    unsupported_os_str += sep + os;
    date = dates[os];
    if (!date) date = "unknown";
    eos_date_str += sep + date;
  }
  unsupported_os_str = substr(unsupported_os_str, strlen(sep));
  eos_date_str = substr(eos_date_str, strlen(sep));

  n_all = max_index(all_oses);
  n_unsupported = max_index(keys(unsupported_oses));

  note = "";
  data = make_array();
  if (n_all == 1)
  {
    data['1. OS fingerprint'] = unsupported_os_str;
    data['2. End-of-life date'] = eos_date_str;
  }
  else
  {
    if (n_unsupported == n_all)
    {
      data['1. OS fingerprints'] = unsupported_os_str;
      data['2. Ends-of-life dates'] = eos_date_str;
      note = '\n' + 'Note that, although the host\'s OS has not been fingerprinted uniquely,' +
             '\n' + 'all the fingerprints are for versions of Novell NetWare that have' +
             '\n' + 'reached their ends-of-life.';
    }
    else if (n_unsupported_oses < n_all && report_paranoia == 2)
    {
      data['1. All OS fingerprints'] = join(all_oses, sep:sep);
      if (n_unsupported == 1)
      {
        data['2. Fingerprint of obsolete OS'] = unsupported_os_str;
        data['3. End-of-life date'] = eos_date_str;
        note = '\n' + 'Note that, although the host\'s OS has not been fingerprinted uniquely,' +
               '\n' + 'one of the fingerprints is for a version of Novell NetWare that has' +
               '\n' + 'reached its end-of-life and the \'Report paranoia\' preference was set' +
               '\n' + 'to \'Paranoid (more false alarms)\'.';
      }
      else
      {
        data['2. Fingerprints of obsolete OSes'] = unsupported_os_str;
        data['3. Ends-of-life dates'] = eos_date_str;
        note = '\n' + 'Note that, although the host\'s OS has not been fingerprinted uniquely,' +
               '\n' + 'some of the fingerprints are for versions of Novell NetWare that have' +
               '\n' + 'reached their ends-of-life and the \'Report paranoia\' preference was' +
               '\n' + 'set to \'Paranoid (more false alarms)\'.';
      }
    }
    else exit(1, "The check resulted in an unexpected condition.");
  }

  max_label_len = 0;
  foreach label (keys(data))
  {
    if (strlen(label) > max_label_len) max_label_len = strlen(label);
  }
  max_label_len -= 3;

  report = '';
  foreach label (sort(keys(data)))
  {
    datum = data[label];
    label = substr(label, 3);
    report += '\n  ' + label + crap(data:" ", length:max_label_len-strlen(label)) + ' : ' + datum;
  }
  label = 'Supported OS';
  report += '\n  ' + label + crap(data:" ", length:max_label_len-strlen(label)) + ' : ' + latest;

  if (note) report += '\n' + note;

  security_hole(port:0, extra:report);
}
else security_hole(0);
