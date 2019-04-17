{panel:title=Description}
{{ !diagnosis}}
{panel}


{panel:title=Consequence}
{{ !consequence}}
{panel}

{panel:title=Solution}
{{ !solution}}
{panel}

{panel:title=Affected Assets}
% for ip in ips:
 * {{ip}}
% end
{panel}

{panel:title=References}
% for ref in references:
 * {{ref}}
% end
{panel}



Please do not delete or modify the ticket assigned tags or title, as they are used to be synced. If the ticket ceases to be recognised, a new ticket will raise.

In the case of the team accepting the risk and wanting to close the ticket, please add the label "*risk_accepted*" to the ticket before closing it.

If server has been decommissioned, please add the label "*server_decommission*" to the ticket before closing it.

If when checking the vulnerability it looks like a false positive, _+please elaborate in a comment+_ and add the label "*false_positive*" before closing it; we will review it and report it to the vendor.
