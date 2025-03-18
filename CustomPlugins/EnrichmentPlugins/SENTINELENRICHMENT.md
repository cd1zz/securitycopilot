# Sentinel Custom Enrichment Plugin Suite  
**Author: Craig Freyman**  

## Sentinel Watchlist Enrichment Plugin  
This enrichment suite provides security analysts with essential skills to interact with Microsoft Sentinel watchlists during investigations. It enables quick retrieval of watchlists and validation of user presence within specific lists, supporting efficient threat hunting and user risk assessments.

### ListSentinelWatchlists  
Retrieve all configured watchlists within Microsoft Sentinel, including their names, aliases, and IDs. Useful for analysts to understand the available context lists during an investigation.

**Example Prompt:** List all watchlists configured in Sentinel.

---

### CheckUserInSentinelWatchlist  
Check if a specific user principal name (UPN) exists within a given Sentinel watchlist. Supports targeted user validation against threat intelligence or risk watchlists.

**Example Prompt:** Is mscott@paper.com present in the UserTravelTracker watchlist? This watchlist tells us who is on vacation, for how long, and where. 

---

This plugin enhances investigation workflows by simplifying watchlist queries and user validation tasks directly from Security Copilot.