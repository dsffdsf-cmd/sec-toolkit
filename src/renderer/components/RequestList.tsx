import React, { useState, useMemo, useCallback } from 'react';
import { HttpRequest } from '../../main/proxy-server';
import { getInvestigationSignals, isInterestingForPentest } from '../../shared/investigation-signals';
import { EmptyState } from './EmptyState';
import './RequestList.css';

interface RequestListProps {
  requests: HttpRequest[];
  selectedRequest: HttpRequest | null;
  onRequestSelect: (request: HttpRequest) => void;
  onSendToRepeater: (request: HttpRequest) => void;
  onSendToScanner: (request: HttpRequest) => void;
  onSendToIntruder?: (request: HttpRequest) => void;
  onCompareWith?: (request: HttpRequest, as: 'A' | 'B') => void;
  getContentTypeColor: (contentType?: string) => string;
  searchInputRef?: React.RefObject<HTMLInputElement | null>;
}

interface GroupedRequests {
  [host: string]: HttpRequest[];
}

interface SavedFilter {
  id: string;
  name: string;
  filter: string;
  methodFilter: string;
  statusFilter: string;
  contentTypeFilter: string;
  isRegex: boolean;
  searchBody: boolean;
  interestingOnly: boolean;
}

interface QuickFilterOption {
  id: string;
  label: string;
  icon: 'api' | 'json' | 'errors' | 'auth' | 'upload' | 'redirect';
  filter: Partial<SearchFilters>;
}

interface SearchFilters {
  text: string;
  method: string;
  status: string;
  contentType: string;
  isRegex: boolean;
  searchBody: boolean;
  interestingOnly: boolean;
  minSize?: number;
  maxSize?: number;
}

// Helper functions defined outside component to avoid hoisting issues
const getHost = (url: string): string => {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
};

const getPath = (url: string): string => {
  try {
    const urlObj = new URL(url);
    return urlObj.pathname + urlObj.search;
  } catch {
    return url;
  }
};

// Check if URL has server-side script extensions that should be highlighted in red
// Check both the full URL and just the path to catch extensions in query params or path
const hasServerScriptExtension = (url: string): boolean => {
  const path = getPath(url).toLowerCase();
  
  // Check for extensions in the path (more reliable)
  // Match .php, .aspx, .asp, .jsp at the end of path segments or before query params
  const extensions = ['.php', '.aspx', '.asp', '.jsp'];
  
  for (const ext of extensions) {
    // Check if extension appears in the path (with optional query params)
    // Match extension followed by ?, #, /, or end of string
    const regex = new RegExp(`\\${ext}(?:[?#]|$|/)`, 'i');
    if (regex.test(path) || path.endsWith(ext)) {
      return true;
    }
  }
  
  return false;
};

// Quick filter presets with semantic SVG icons (consistent across platforms)
const QUICK_FILTERS: QuickFilterOption[] = [
  { id: 'api', label: 'API', icon: 'api', filter: { text: '/api/', searchBody: false } },
  { id: 'json', label: 'JSON', icon: 'json', filter: { contentType: 'json' } },
  { id: 'errors', label: 'Errors', icon: 'errors', filter: { status: '4xx,5xx' } },
  { id: 'auth', label: 'Auth', icon: 'auth', filter: { text: 'auth|login|token|session|oauth', isRegex: true } },
  { id: 'upload', label: 'Uploads', icon: 'upload', filter: { contentType: 'multipart' } },
  { id: 'redirect', label: 'Redirects', icon: 'redirect', filter: { status: '3xx' } },
];

const ICON_SIZE = 14;
const ICON_STROKE = 2.5;
const svgCommon = {
  width: ICON_SIZE,
  height: ICON_SIZE,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: ICON_STROKE,
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
};

function QuickFilterIcon({ name }: { name: string }) {
  switch (name) {
    case 'api':
      return <svg {...svgCommon} aria-hidden><path d="M13 2L3 14h6l-2 8 10-12h-6l2-8z" /></svg>;
    case 'json':
      return <svg {...svgCommon} aria-hidden><path d="M8 4c-2 0-3 1.5-3 4v8c0 2.5 1 4 3 4M16 4c2 0 3 1.5 3 4v8c0 2.5-1 4-3 4M8 8h1M15 8h1M8 16h1M15 16h1" /></svg>;
    case 'errors':
      return <svg {...svgCommon} aria-hidden><circle cx="12" cy="12" r="9" strokeWidth={ICON_STROKE} /><path d="M15 9l-6 6M9 9l6 6" strokeWidth={ICON_STROKE} /></svg>;
    case 'auth':
      return <svg {...svgCommon} aria-hidden><rect x="4" y="11" width="16" height="10" rx="2" strokeWidth={ICON_STROKE} /><path d="M8 11V7a4 4 0 1 1 8 0v4" strokeWidth={ICON_STROKE} /></svg>;
    case 'upload':
      return <svg {...svgCommon} aria-hidden><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" strokeWidth={ICON_STROKE} /><polyline points="17 8 12 3 7 8" strokeWidth={ICON_STROKE} /><line x1="12" y1="3" x2="12" y2="15" strokeWidth={ICON_STROKE} /></svg>;
    case 'redirect':
      return <svg {...svgCommon} aria-hidden><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" strokeWidth={ICON_STROKE} /><polyline points="15 3 21 3 21 9" strokeWidth={ICON_STROKE} /><line x1="10" y1="14" x2="21" y2="3" strokeWidth={ICON_STROKE} /></svg>;
    default:
      return null;
  }
}

// Bar icons for settings, interesting, save, clear, expand/collapse, document, delete
function BarIcon({ name }: { name: 'settings' | 'interesting' | 'save' | 'clear' | 'expandAll' | 'collapseAll' | 'document' | 'delete' }) {
  switch (name) {
    case 'settings':
      return <svg {...svgCommon} aria-hidden><circle cx="12" cy="12" r="3" strokeWidth={ICON_STROKE} /><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" strokeWidth={ICON_STROKE} /></svg>;
    case 'interesting':
      return <svg {...svgCommon} aria-hidden><circle cx="12" cy="12" r="10" strokeWidth={ICON_STROKE} /><path d="M12 2l1.5 4.5L18 8l-3.5 2.5L16 15l-4-2.5L8 15l1-4.5L6 8l4.5-1.5L12 2z" strokeWidth={ICON_STROKE} fill="none" /></svg>;
    case 'save':
      return <svg {...svgCommon} aria-hidden><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z" strokeWidth={ICON_STROKE} /><polyline points="17 21 17 13 7 13 7 21" strokeWidth={ICON_STROKE} /><polyline points="7 3 7 8 15 8" strokeWidth={ICON_STROKE} /></svg>;
    case 'clear':
      return <svg {...svgCommon} aria-hidden><circle cx="12" cy="12" r="10" strokeWidth={ICON_STROKE} /><path d="M15 9l-6 6M9 9l6 6" strokeWidth={ICON_STROKE} /></svg>;
    case 'expandAll':
      return <svg {...svgCommon} aria-hidden><rect x="3" y="3" width="7" height="7" rx="1" strokeWidth={ICON_STROKE} /><rect x="14" y="3" width="7" height="7" rx="1" strokeWidth={ICON_STROKE} /><rect x="3" y="14" width="7" height="7" rx="1" strokeWidth={ICON_STROKE} /><rect x="14" y="14" width="7" height="7" rx="1" strokeWidth={ICON_STROKE} /></svg>;
    case 'collapseAll':
      return <svg {...svgCommon} aria-hidden><line x1="8" y1="6" x2="21" y2="6" strokeWidth={ICON_STROKE} /><line x1="8" y1="12" x2="21" y2="12" strokeWidth={ICON_STROKE} /><line x1="8" y1="18" x2="21" y2="18" strokeWidth={ICON_STROKE} /><line x1="3" y1="6" x2="3.01" y2="6" strokeWidth={ICON_STROKE} /><line x1="3" y1="12" x2="3.01" y2="12" strokeWidth={ICON_STROKE} /><line x1="3" y1="18" x2="3.01" y2="18" strokeWidth={ICON_STROKE} /></svg>;
    case 'document':
      return <svg {...svgCommon} aria-hidden><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" strokeWidth={ICON_STROKE} /><polyline points="14 2 14 8 20 8" strokeWidth={ICON_STROKE} /><line x1="16" y1="13" x2="8" y2="13" strokeWidth={ICON_STROKE} /><line x1="16" y1="17" x2="8" y2="17" strokeWidth={ICON_STROKE} /><polyline points="10 9 9 9 8 9" strokeWidth={ICON_STROKE} /></svg>;
    case 'delete':
      return <svg {...svgCommon} aria-hidden><line x1="18" y1="6" x2="6" y2="18" strokeWidth={ICON_STROKE} /><line x1="6" y1="6" x2="18" y2="18" strokeWidth={ICON_STROKE} /></svg>;
    default:
      return null;
  }
}

const STATUS_FILTERS = [
  { value: '', label: 'All statuses' },
  { value: '2xx', label: '2xx Success' },
  { value: '3xx', label: '3xx Redirect' },
  { value: '4xx', label: '4xx Client Error' },
  { value: '5xx', label: '5xx Server Error' },
  { value: '4xx,5xx', label: '4xx/5xx Errors' },
  { value: 'pending', label: 'Pending' },
];

const CONTENT_TYPE_FILTERS = [
  { value: '', label: 'All types' },
  { value: 'json', label: 'JSON' },
  { value: 'html', label: 'HTML' },
  { value: 'javascript', label: 'JavaScript' },
  { value: 'css', label: 'CSS' },
  { value: 'image', label: 'Images' },
  { value: 'xml', label: 'XML' },
  { value: 'form', label: 'Form Data' },
  { value: 'multipart', label: 'Multipart / Uploads' },
];

const RequestList: React.FC<RequestListProps> = ({
  requests,
  selectedRequest,
  onRequestSelect,
  onSendToRepeater,
  onSendToScanner,
  onSendToIntruder,
  onCompareWith,
  getContentTypeColor,
  searchInputRef,
}) => {
  const [filter, setFilter] = useState('');
  const [methodFilter, setMethodFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [contentTypeFilter, setContentTypeFilter] = useState<string>('');
  const [selectedTags, setSelectedTags] = useState<Set<string>>(new Set());
  const [interestingOnly, setInterestingOnly] = useState(false);
  const [expandedHosts, setExpandedHosts] = useState<Set<string>>(new Set());
  const [isRegex, setIsRegex] = useState(false);
  const [searchBody, setSearchBody] = useState(false);
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);
  const [savedFilters, setSavedFilters] = useState<SavedFilter[]>(() => {
    try {
      const saved = localStorage.getItem('cleantraffic-saved-filters');
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });
  const [activeQuickFilters, setActiveQuickFilters] = useState<Set<string>>(new Set());

  const METHOD_OPTIONS = ['', 'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'] as const;

  // Save current filters
  const saveCurrentFilter = useCallback(() => {
    const name = prompt('Enter a name for this filter:');
    if (!name) return;

    const newFilter: SavedFilter = {
      id: Date.now().toString(),
      name,
      filter,
      methodFilter,
      statusFilter,
      contentTypeFilter,
      isRegex,
      searchBody,
      interestingOnly,
    };

    const updated = [...savedFilters, newFilter];
    setSavedFilters(updated);
    localStorage.setItem('cleantraffic-saved-filters', JSON.stringify(updated));
  }, [filter, methodFilter, statusFilter, contentTypeFilter, isRegex, searchBody, interestingOnly, savedFilters]);

  // Load a saved filter
  const loadSavedFilter = useCallback((saved: SavedFilter) => {
    setFilter(saved.filter);
    setMethodFilter(saved.methodFilter);
    setStatusFilter(saved.statusFilter);
    setContentTypeFilter(saved.contentTypeFilter);
    setIsRegex(saved.isRegex);
    setSearchBody(saved.searchBody);
    setInterestingOnly(saved.interestingOnly);
  }, []);

  // Delete a saved filter
  const deleteSavedFilter = useCallback((id: string) => {
    const updated = savedFilters.filter(f => f.id !== id);
    setSavedFilters(updated);
    localStorage.setItem('cleantraffic-saved-filters', JSON.stringify(updated));
  }, [savedFilters]);

  // Toggle quick filter
  const toggleQuickFilter = useCallback((quickFilter: QuickFilterOption) => {
    setActiveQuickFilters(prev => {
      const newSet = new Set(prev);
      if (newSet.has(quickFilter.id)) {
        newSet.delete(quickFilter.id);
        // Reset the filter values this quick filter set
        if (quickFilter.filter.text) setFilter('');
        if (quickFilter.filter.status) setStatusFilter('');
        if (quickFilter.filter.contentType) setContentTypeFilter('');
        if (quickFilter.filter.isRegex !== undefined) setIsRegex(false);
        if (quickFilter.filter.searchBody !== undefined) setSearchBody(false);
      } else {
        newSet.add(quickFilter.id);
        // Apply the quick filter
        if (quickFilter.filter.text) setFilter(quickFilter.filter.text);
        if (quickFilter.filter.status) setStatusFilter(quickFilter.filter.status);
        if (quickFilter.filter.contentType) setContentTypeFilter(quickFilter.filter.contentType);
        if (quickFilter.filter.isRegex !== undefined) setIsRegex(quickFilter.filter.isRegex);
        if (quickFilter.filter.searchBody !== undefined) setSearchBody(quickFilter.filter.searchBody);
      }
      return newSet;
    });
  }, []);

  // Clear all filters
  const clearAllFilters = useCallback(() => {
    setFilter('');
    setMethodFilter('');
    setStatusFilter('');
    setContentTypeFilter('');
    setIsRegex(false);
    setSearchBody(false);
    setInterestingOnly(false);
    setSelectedTags(new Set());
    setActiveQuickFilters(new Set());
  }, []);

  // Match status code against filter
  const matchesStatusFilter = useCallback((status: number | undefined, statusFilterValue: string): boolean => {
    if (!statusFilterValue) return true;
    if (statusFilterValue === 'pending') return !status;
    
    const filters = statusFilterValue.split(',');
    for (const f of filters) {
      const trimmed = f.trim();
      if (trimmed === '2xx' && status && status >= 200 && status < 300) return true;
      if (trimmed === '3xx' && status && status >= 300 && status < 400) return true;
      if (trimmed === '4xx' && status && status >= 400 && status < 500) return true;
      if (trimmed === '5xx' && status && status >= 500) return true;
    }
    return false;
  }, []);

  // Match content type against filter
  const matchesContentTypeFilter = useCallback((contentType: string | undefined, ctFilter: string): boolean => {
    if (!ctFilter) return true;
    if (!contentType) return false;
    
    const ct = contentType.toLowerCase();
    switch (ctFilter) {
      case 'json': return ct.includes('json');
      case 'html': return ct.includes('html');
      case 'javascript': return ct.includes('javascript') || ct.includes('ecmascript');
      case 'css': return ct.includes('css');
      case 'image': return ct.includes('image');
      case 'xml': return ct.includes('xml');
      case 'form': return ct.includes('form-data') || ct.includes('x-www-form-urlencoded');
      case 'multipart': return ct.includes('multipart');
      default: return ct.includes(ctFilter);
    }
  }, []);

  // Group requests by host
  const groupedRequests = useMemo(() => {
    const grouped: GroupedRequests = {};
    
    requests.forEach((req) => {
      const host = getHost(req.url);
      if (!grouped[host]) {
        grouped[host] = [];
      }
      grouped[host].push(req);
    });

    // Sort hosts alphabetically
    const sortedHosts = Object.keys(grouped).sort();
    const sortedGrouped: GroupedRequests = {};
    sortedHosts.forEach(host => {
      // Sort requests within each host by timestamp (newest first)
      sortedGrouped[host] = grouped[host].sort((a, b) => b.timestamp - a.timestamp);
    });

    return sortedGrouped;
  }, [requests]);

  // Get all unique tags from requests
  const allTags = useMemo(() => {
    const tagsSet = new Set<string>();
    requests.forEach(req => {
      if (req.tags) {
        req.tags.forEach(tag => tagsSet.add(tag));
      }
    });
    return Array.from(tagsSet).sort();
  }, [requests]);

  // Helper function to match text (supports regex or plain text)
  const matchesTextFilter = useCallback((req: HttpRequest, host: string, searchText: string): boolean => {
    if (!searchText) return true;

    try {
      if (isRegex) {
        const regex = new RegExp(searchText, 'i');
        const basicMatch = 
          regex.test(req.method) ||
          regex.test(req.url) ||
          regex.test(host) ||
          (req.status ? regex.test(req.status.toString()) : false) ||
          (req.notes ? regex.test(req.notes) : false);

        if (basicMatch) return true;

        // Search body if enabled
        if (searchBody) {
          if (req.body && regex.test(req.body)) return true;
          if (req.responseBody && regex.test(req.responseBody)) return true;
        }

        return false;
      } else {
        const search = searchText.toLowerCase();
        const basicMatch = 
          req.method.toLowerCase().includes(search) ||
          req.url.toLowerCase().includes(search) ||
          host.toLowerCase().includes(search) ||
          req.status?.toString().includes(search) ||
          req.notes?.toLowerCase().includes(search);

        if (basicMatch) return true;

        // Search body if enabled
        if (searchBody) {
          if (req.body && req.body.toLowerCase().includes(search)) return true;
          if (req.responseBody && req.responseBody.toLowerCase().includes(search)) return true;
        }

        return false;
      }
    } catch {
      // Invalid regex, fall back to plain text (apply same fields as non-regex branch)
      const search = searchText.toLowerCase();
      const basicMatch =
        req.method.toLowerCase().includes(search) ||
        req.url.toLowerCase().includes(search) ||
        host.toLowerCase().includes(search) ||
        (req.status ? req.status.toString().includes(search) : false) ||
        (req.notes ? req.notes.toLowerCase().includes(search) : false);
      if (basicMatch) return true;
      if (searchBody) {
        if (req.body && req.body.toLowerCase().includes(search)) return true;
        if (req.responseBody && req.responseBody.toLowerCase().includes(search)) return true;
      }
      return false;
    }
  }, [isRegex, searchBody]);

  // Filter grouped requests
  const filteredGroupedRequests = useMemo(() => {
    let filtered = groupedRequests;

    // Apply text filter
    if (filter) {
      const textFiltered: GroupedRequests = {};

      Object.entries(filtered).forEach(([host, hostRequests]) => {
        const matchingRequests = hostRequests.filter((req) => matchesTextFilter(req, host, filter));

        if (matchingRequests.length > 0 || host.toLowerCase().includes(filter.toLowerCase())) {
          textFiltered[host] = matchingRequests.length > 0 ? matchingRequests : hostRequests;
        }
      });

      filtered = textFiltered;
    }

    // Apply tag filter
    if (selectedTags.size > 0) {
      const tagFiltered: GroupedRequests = {};
      Object.entries(filtered).forEach(([host, hostRequests]) => {
        const matchingRequests = hostRequests.filter((req) => {
          if (!req.tags || req.tags.length === 0) return false;
          return Array.from(selectedTags).some(tag => req.tags!.includes(tag));
        });
        if (matchingRequests.length > 0) tagFiltered[host] = matchingRequests;
      });
      filtered = tagFiltered;
    }

    // Method filter (GET, POST, PUT, PATCH, DELETE, etc.)
    if (methodFilter) {
      const m = methodFilter.toUpperCase();
      const methodFiltered: GroupedRequests = {};
      Object.entries(filtered).forEach(([host, hostRequests]) => {
        const matching = hostRequests.filter((req) => (req.method || '').toUpperCase() === m);
        if (matching.length > 0) methodFiltered[host] = matching;
      });
      filtered = methodFiltered;
    }

    // Status filter
    if (statusFilter) {
      const statusFiltered: GroupedRequests = {};
      Object.entries(filtered).forEach(([host, hostRequests]) => {
        const matching = hostRequests.filter((req) => matchesStatusFilter(req.status, statusFilter));
        if (matching.length > 0) statusFiltered[host] = matching;
      });
      filtered = statusFiltered;
    }

    // Content type filter
    if (contentTypeFilter) {
      const ctFiltered: GroupedRequests = {};
      Object.entries(filtered).forEach(([host, hostRequests]) => {
        const matching = hostRequests.filter((req) => matchesContentTypeFilter(req.contentType, contentTypeFilter));
        if (matching.length > 0) ctFiltered[host] = matching;
      });
      filtered = ctFiltered;
    }

    // Pentest: "Interesting only" – high-value, sensitive params, IDOR candidates, auth
    if (interestingOnly) {
      const interestingFiltered: GroupedRequests = {};
      Object.entries(filtered).forEach(([host, hostRequests]) => {
        const matching = hostRequests.filter(isInterestingForPentest);
        if (matching.length > 0) interestingFiltered[host] = matching;
      });
      filtered = interestingFiltered;
    }

    return filtered;
  }, [groupedRequests, filter, methodFilter, statusFilter, contentTypeFilter, selectedTags, interestingOnly, matchesTextFilter, matchesStatusFilter, matchesContentTypeFilter]);

  // Auto-expand hosts when filtering
  React.useEffect(() => {
    if (filter || methodFilter || statusFilter || contentTypeFilter || interestingOnly || selectedTags.size > 0) {
      const newExpanded = new Set<string>();
      Object.keys(filteredGroupedRequests).forEach(host => {
        newExpanded.add(host);
      });
      setExpandedHosts(newExpanded);
    }
  }, [filter, methodFilter, statusFilter, contentTypeFilter, interestingOnly, selectedTags, filteredGroupedRequests]);

  const toggleHost = (host: string) => {
    const newExpanded = new Set(expandedHosts);
    if (newExpanded.has(host)) {
      newExpanded.delete(host);
    } else {
      newExpanded.add(host);
    }
    setExpandedHosts(newExpanded);
  };

  const expandAllHosts = useCallback(() => {
    const allHosts = new Set<string>(Object.keys(filteredGroupedRequests));
    setExpandedHosts(allHosts);
  }, [filteredGroupedRequests]);

  const collapseAllHosts = useCallback(() => {
    setExpandedHosts(new Set());
  }, []);

  // Check if any filters are active
  const hasActiveFilters = filter || methodFilter || statusFilter || contentTypeFilter || 
    interestingOnly || selectedTags.size > 0 || activeQuickFilters.size > 0;

  const getStatusColor = (status?: number): string => {
    if (!status) return '#999999';
    if (status >= 200 && status < 300) return '#2ecc71';
    if (status >= 300 && status < 400) return '#3498db';
    if (status >= 400 && status < 500) return '#f39c12';
    if (status >= 500) return '#e74c3c';
    return '#999999';
  };

  const getSourceIcon = (source: string): string => {
    switch (source) {
      case 'chrome':
        return '🌐';
      case 'mobile':
        return '📱';
      case 'firefox':
        return '🦊';
      default:
        return '🔗';
    }
  };

  const handleContextMenu = (e: React.MouseEvent, request: HttpRequest) => {
    e.preventDefault();
    e.stopPropagation();
    
    // Check if it's a JS file
    const isJS = request.contentType?.includes('javascript') || 
                request.url.includes('.js') ||
                request.url.includes('/js/');
    
    const menu = document.createElement('div');
    menu.className = 'context-menu';
    let menuItems = `
      <div class="context-menu-item" data-action="repeater">Send to Repeater</div>
      <div class="context-menu-item" data-action="copy-curl">Copy as cURL</div>
    `;
    if (isJS) {
      menuItems = `<div class="context-menu-item" data-action="scanner">Send to Scanner</div>` + menuItems;
    }
    if (onSendToIntruder) {
      menuItems = `<div class="context-menu-item" data-action="intruder">Send to Intruder</div>` + menuItems;
    }
    if (onCompareWith) {
      menuItems += `
        <div class="context-menu-item" data-action="compare-a">Compare with… (set as A)</div>
        <div class="context-menu-item" data-action="compare-b">Compare with… (set as B)</div>
      `;
    }
    menu.innerHTML = menuItems;
    menu.style.position = 'fixed';
    menu.style.left = `${e.clientX}px`;
    menu.style.top = `${e.clientY}px`;
    menu.style.zIndex = '10000';
    document.body.appendChild(menu);

    const handleClick = (event: Event) => {
      const target = (event.target as HTMLElement).closest('.context-menu-item');
      if (target) {
        const action = target.getAttribute('data-action');
        if (action === 'scanner') {
          onSendToScanner(request);
        } else if (action === 'repeater') {
          onSendToRepeater(request);
        } else if (action === 'intruder' && onSendToIntruder) {
          onSendToIntruder(request);
        } else if (action === 'compare-a' && onCompareWith) {
          onCompareWith(request, 'A');
        } else if (action === 'compare-b' && onCompareWith) {
          onCompareWith(request, 'B');
        } else if (action === 'copy-curl') {
          copyAsCurl(request);
        }
      }
      if (document.body.contains(menu)) {
        document.body.removeChild(menu);
      }
      document.removeEventListener('click', handleClick);
    };

    setTimeout(() => {
      document.addEventListener('click', handleClick);
    }, 0);
  };

  const copyAsCurl = (request: HttpRequest) => {
    let curl = `curl -X ${request.method} '${request.url}'`;

    // Add headers
    Object.entries(request.headers).forEach(([key, value]) => {
      if (key.toLowerCase() !== 'host' && key.toLowerCase() !== 'content-length') {
        curl += ` \\\n  -H '${key}: ${value}'`;
      }
    });

    // Add body
    if (request.body && request.body.length > 0) {
      curl += ` \\\n  -d '${request.body.replace(/'/g, "'\\''")}'`;
    }

    navigator.clipboard.writeText(curl);
  };

  const getHostIconClass = (host: string): string => {
    if (host.includes('api.')) return 'host-icon-api';
    if (host.includes('cdn.') || host.includes('static.')) return 'host-icon-cdn';
    if (host.includes('www.')) return 'host-icon-www';
    return 'host-icon-default';
  };

  const totalRequests = Object.values(filteredGroupedRequests).reduce((sum, reqs) => sum + reqs.length, 0);

  return (
    <div className="request-list">
      <div className="request-list-header">
        <div className="request-list-title-row">
          <div className="request-list-title">Requests</div>
          <span className="request-list-methods-hint" title="All HTTP methods are captured and can be filtered">GET, POST, PUT, PATCH, DELETE…</span>
        </div>
        <div className="request-count">
          {totalRequests} requests
          {Object.keys(filteredGroupedRequests).length > 0 && (
            <span className="host-count-info"> ({Object.keys(filteredGroupedRequests).length} hosts)</span>
          )}
        </div>
      </div>

      {/* Quick Filters */}
      <div className="quick-filters">
        {QUICK_FILTERS.map(qf => (
          <button
            type="button"
            key={qf.id}
            className={`quick-filter-btn ${activeQuickFilters.has(qf.id) ? 'active' : ''}`}
            onClick={() => toggleQuickFilter(qf)}
            title={`Quick filter: ${qf.label}`}
          >
            <span className="quick-filter-icon"><QuickFilterIcon name={qf.icon} /></span>
            {qf.label}
          </button>
        ))}
      </div>

      <div className="request-list-filter">
        <div className="filter-row">
          <div className="search-input-wrapper">
            <input
              ref={searchInputRef as React.RefObject<HTMLInputElement>}
              type="text"
              placeholder={isRegex ? "Regex pattern..." : "Filter by method, host, path, status, notes..."}
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className={`filter-input ${isRegex ? 'regex-mode' : ''}`}
            />
            <div className="search-options">
              <button
                type="button"
                className={`search-option-btn ${isRegex ? 'active' : ''}`}
                onClick={() => setIsRegex(v => !v)}
                title="Toggle regex mode"
              >
                .*
              </button>
              <button
                type="button"
                className={`search-option-btn ${searchBody ? 'active' : ''}`}
                onClick={() => setSearchBody(v => !v)}
                title="Search in request/response body"
              >
                <span className="bar-icon-wrap"><BarIcon name="document" /></span>
              </button>
            </div>
          </div>
          <select
            className="method-filter-select"
            value={methodFilter}
            onChange={(e) => setMethodFilter(e.target.value)}
            title="Filter by HTTP method"
            aria-label="Filter by HTTP method"
          >
            <option value="">All methods</option>
            {METHOD_OPTIONS.filter(Boolean).map((m) => (
              <option key={m} value={m}>{m}</option>
            ))}
          </select>
          <button
            type="button"
            className={`filter-toggle-btn ${showAdvancedFilters ? 'active' : ''}`}
            onClick={() => setShowAdvancedFilters(v => !v)}
            title="Show advanced filters"
          >
            <span className="bar-icon-wrap"><BarIcon name="settings" /></span>
          </button>
          <button
            type="button"
            className={`interesting-toggle ${interestingOnly ? 'active' : ''}`}
            onClick={() => setInterestingOnly((v) => !v)}
            title="Show only high-value / pentest-interesting requests"
          >
            <span className="interesting-icon"><BarIcon name="interesting" /></span>
            Interesting
          </button>
        </div>

        {/* Advanced Filters */}
        {showAdvancedFilters && (
          <div className="advanced-filters">
            <div className="advanced-filter-row">
              <select
                className="status-filter-select"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                title="Filter by status code"
              >
                {STATUS_FILTERS.map(sf => (
                  <option key={sf.value} value={sf.value}>{sf.label}</option>
                ))}
              </select>
              <select
                className="content-type-filter-select"
                value={contentTypeFilter}
                onChange={(e) => setContentTypeFilter(e.target.value)}
                title="Filter by content type"
              >
                {CONTENT_TYPE_FILTERS.map(ct => (
                  <option key={ct.value} value={ct.value}>{ct.label}</option>
                ))}
              </select>
              <button
                type="button"
                className="save-filter-btn"
                onClick={saveCurrentFilter}
                title="Save current filter"
                disabled={!filter && !methodFilter && !statusFilter && !contentTypeFilter && !interestingOnly}
              >
                <span className="bar-icon-wrap"><BarIcon name="save" /></span> Save
              </button>
              {hasActiveFilters && (
                <button
                  type="button"
                  className="clear-filters-btn"
                  onClick={clearAllFilters}
                  title="Clear all filters"
                >
                  <span className="bar-icon-wrap"><BarIcon name="clear" /></span> Clear
                </button>
              )}
            </div>

            {/* Saved Filters */}
            {savedFilters.length > 0 && (
              <div className="saved-filters">
                <span className="saved-filters-label">Saved:</span>
                {savedFilters.map(sf => (
                  <div key={sf.id} className="saved-filter-item">
                    <button
                      type="button"
                      className="saved-filter-btn"
                      onClick={() => loadSavedFilter(sf)}
                      title={`Load: ${sf.filter || 'No text filter'} ${sf.methodFilter || ''} ${sf.statusFilter || ''}`}
                    >
                      {sf.name}
                    </button>
                    <button
                      type="button"
                      className="saved-filter-delete"
                      onClick={() => deleteSavedFilter(sf.id)}
                      title="Delete this filter"
                    >
                      <BarIcon name="delete" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Host Expansion Controls */}
      <div className="host-controls">
        <button
          type="button"
          className="host-control-btn"
          onClick={expandAllHosts}
          title="Expand all hosts"
        >
          <span className="bar-icon-wrap"><BarIcon name="expandAll" /></span> Expand All
        </button>
        <button
          type="button"
          className="host-control-btn"
          onClick={collapseAllHosts}
          title="Collapse all hosts"
        >
          <span className="bar-icon-wrap"><BarIcon name="collapseAll" /></span> Collapse All
        </button>
      </div>

      {allTags.length > 0 && (
        <div className="tags-filter">
          <div className="tags-filter-label">Filter by tags:</div>
          <div className="tags-filter-list">
            {allTags.map(tag => (
              <button
                type="button"
                key={tag}
                className={`tag-filter-btn ${selectedTags.has(tag) ? 'active' : ''}`}
                onClick={() => {
                  const newSelected = new Set(selectedTags);
                  if (newSelected.has(tag)) {
                    newSelected.delete(tag);
                  } else {
                    newSelected.add(tag);
                  }
                  setSelectedTags(newSelected);
                }}
              >
                {tag}
                {selectedTags.has(tag) && (
                  <span className="tag-filter-check">✓</span>
                )}
              </button>
            ))}
            {selectedTags.size > 0 && (
              <button
                type="button"
                className="tag-filter-clear"
                onClick={() => setSelectedTags(new Set())}
              >
                Clear
              </button>
            )}
          </div>
        </div>
      )}

      <div
        className={`request-list-tree ${Object.keys(filteredGroupedRequests).length === 0 ? 'is-empty' : ''}`}
      >
        {Object.entries(filteredGroupedRequests).map(([host, hostRequests]) => {
          const isExpanded = expandedHosts.has(host);
          const requestCount = hostRequests.length;
          
          return (
            <div key={host} className="host-group">
              <div 
                className="host-header"
                onClick={() => toggleHost(host)}
              >
                <svg 
                  className={`expand-icon ${isExpanded ? 'expanded' : ''}`}
                  width="12" 
                  height="12" 
                  viewBox="0 0 12 12" 
                  fill="none"
                >
                  <path 
                    d="M4.5 3L7.5 6L4.5 9" 
                    stroke="currentColor" 
                    strokeWidth="1.5" 
                    strokeLinecap="round" 
                    strokeLinejoin="round"
                  />
                </svg>
                <span className={`host-icon ${getHostIconClass(host)}`}></span>
                <span className="host-name">{host}</span>
                <span className="host-count">{requestCount}</span>
              </div>
              
              {isExpanded && (
                <div className="host-requests">
                  {hostRequests.map((request) => {
                    const isSelected = selectedRequest?.id === request.id;
                    const color = getContentTypeColor(request.contentType);
                    const signals = getInvestigationSignals(request);
                    const showInvestigate = signals.risk === 'high' || signals.risk === 'medium';
                    return (
                      <div
                        key={request.id}
                        className={`request-row ${isSelected ? 'selected' : ''} ${showInvestigate ? 'has-investigate' : ''}`}
                        onClick={(e) => {
                          e.stopPropagation();
                          onRequestSelect(request);
                        }}
                        onContextMenu={(e) => handleContextMenu(e, request)}
                      >
                        <div className="row-indicator" style={{ backgroundColor: color }}></div>
                        {showInvestigate && (
                          <span
                            className={`investigate-badge risk-${signals.risk}`}
                            title={signals.reasons.slice(0, 3).join(' • ')}
                          >
                            {signals.risk === 'high' ? 'H' : 'M'}
                          </span>
                        )}
                        <div className="request-method">
                          <span className={`method-badge ${(request.method || 'GET').toUpperCase()}`}>
                            {request.method || '—'}
                          </span>
                        </div>
                        <div className="request-status">
                          <span 
                            className="status-badge"
                            style={{ color: getStatusColor(request.status) }}
                          >
                            {request.status || '—'}
                          </span>
                        </div>
                        <div 
                          className={`request-path ${hasServerScriptExtension(request.url) ? 'server-script-url' : ''}`}
                          title={getPath(request.url)}
                        >
                          {getPath(request.url)}
                        </div>
                        <div className="request-time">
                          {new Date(request.timestamp).toLocaleTimeString()}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
        
        {Object.keys(filteredGroupedRequests).length === 0 && (
          <EmptyState
            icon="inbox"
            title="No requests captured yet"
            subtitle="Launch browser to start intercepting traffic"
            brandName="CleanTraffic"
          />
        )}
      </div>
    </div>
  );
};

export default RequestList;
