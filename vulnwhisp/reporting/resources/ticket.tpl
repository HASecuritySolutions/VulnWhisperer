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

If server has been decomissioned, please add the label "*server_decomission*" to the ticket before closing it.
