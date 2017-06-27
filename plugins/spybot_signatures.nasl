#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58343);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/03/15 00:44:05 $");

  script_name(english:"Spybot Search & Destroy Signature Update Check");
  script_summary(english:"Checks to see when the signatures have been last updated");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an outdated version of the Spybot Search &
Destroy detection rule signatures, or it has never been updated."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has an outdated version of the Spybot Search &
Destroy detection rule signatures, or it has never been updated.  As a
result, the remote host might contain malware."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.safer-networking.org/en/faq/index.html");
  script_set_attribute(attribute:"solution", value:"Update Spybot Search & Destroy signatures.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:safer-networking:spybot_search_and_destroy");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("spybot_detection.nasl");
  script_require_keys("SMB/SpybotSD/Installed");
  
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item("SMB/transport");

get_kb_item_or_exit("SMB/SpybotSD/Installed");
sigs_present = get_kb_item_or_exit("SMB/SpybotSD/signatures_present");

signatures_target = get_kb_list("SMB/SpybotSD/signatures_target/*");
signatures_vendor = get_kb_list("SMB/SpybotSD/signatures_vendor/*");

report = "";

if (!sigs_present)
  report =   '\nNo detection ruleset installed.';
else
{
  foreach sig (keys(signatures_vendor))
  {
    sig = sig - "SMB/SpybotSD/signatures_vendor/";
    signature_vendor = get_kb_item("SMB/SpybotSD/signatures_vendor/" + sig);
    signature_target = get_kb_item("SMB/SpybotSD/signatures_target/" + sig);

    if(isnull(signature_target))
    {
      report += '\nMissing Signature : ' + sig;
      continue;
    }
    sig_vendor_yyyymmdd = substr(signature_vendor, 6, 9) + 
                          substr(signature_vendor, 0, 1) +
                          substr(signature_vendor, 3, 4);

    sig_target_yyyymmdd = substr(signature_target, 6, 9) + 
                          substr(signature_target, 0, 1) +
                          substr(signature_target, 3, 4);
  
    if(int(sig_vendor_yyyymmdd) > int(sig_target_yyyymmdd)) 
    {
      report =   '\nSignature out of date : ' + sig;
      report +=   '\n  Current Signature Update Date   : ' + signature_target;
      report +=  '\n  Latest Signature Available Date  : ' + signature_vendor + '\n';
    }
  }
} 

if (report != "")
{
  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port);
  exit(0);
}
else exit(0, "Spybot Search & Destroy signatures are up-to-date.");
