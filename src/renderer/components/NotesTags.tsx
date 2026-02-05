import React, { useState, useEffect } from 'react';
import { HttpRequest } from '../../main/proxy-server';
import './NotesTags.css';

export type FindingStatus = 'open' | 'confirmed' | 'false positive' | 'fixed';
const FINDING_STATUSES: FindingStatus[] = ['open', 'confirmed', 'false positive', 'fixed'];

interface NotesTagsProps {
  request: HttpRequest;
  onUpdate: (requestId: string, notes: string, tags: string[]) => void;
}

const STATUS_REG = /Status:\s*(open|confirmed|false\s*positive|fixed)/i;
function parseFindingBlocks(notesText: string): { block: string; status: FindingStatus; ruleId?: string; severity?: string; index: number }[] {
  if (!notesText?.trim()) return [];
  const rawBlocks = notesText.split(/\n={60,}\n\n/);
  const out: { block: string; status: FindingStatus; ruleId?: string; severity?: string; index: number }[] = [];
  rawBlocks.forEach((block, i) => {
    const t = block.trim();
    if (!t) return;
    const isFinding = /Rule ID:|Severity:|Security Finding|Context Code/i.test(t);
    if (!isFinding) return;
    const statusMatch = t.match(STATUS_REG);
    const statusRaw = statusMatch ? statusMatch[1].toLowerCase().replace(/\s*positive\s*/g, ' positive ') : 'open';
    const status: FindingStatus = statusRaw === 'false positive' ? 'false positive' : (statusRaw as FindingStatus);
    const ruleIdMatch = t.match(/Rule ID:\s*([^\n]+)/i);
    const severityMatch = t.match(/Severity:\s*([^\n]+)/i);
    out.push({
      block,
      status,
      ruleId: ruleIdMatch?.[1]?.trim(),
      severity: severityMatch?.[1]?.trim(),
      index: i,
    });
  });
  return out;
}

function setStatusInBlock(block: string, newStatus: FindingStatus): string {
  const trimmed = block.trim();
  if (STATUS_REG.test(trimmed)) {
    return trimmed.replace(STATUS_REG, `Status: ${newStatus}`);
  }
  return trimmed + (trimmed.endsWith('\n') ? '' : '\n') + `Status: ${newStatus}`;
}

const NotesTags: React.FC<NotesTagsProps> = ({ request, onUpdate }) => {
  const [notes, setNotes] = useState<string>(request.notes || '');
  const [tags, setTags] = useState<string[]>(request.tags || []);
  const [newTag, setNewTag] = useState<string>('');
  const [isEditing, setIsEditing] = useState<boolean>(false);

  // Predefined tag suggestions
  const suggestedTags = [
    'vulnerable', 'interesting', 'API', 'auth', 'sensitive', 
    'error', 'slow', 'large', 'redirect', 'cached', 'custom',
    'XSS', 'SQLi', 'CSRF', 'SSRF', 'RCE', 'LFI', 'RFI'
  ];

  useEffect(() => {
    setNotes(request.notes || '');
    setTags(request.tags || []);
  }, [request.id, request.notes, request.tags]);

  const handleNotesChange = (value: string) => {
    setNotes(value);
    setIsEditing(true);
  };

  const handleSave = () => {
    onUpdate(request.id, notes, tags);
    setIsEditing(false);
  };

  const handleAddTag = (tag: string) => {
    const trimmedTag = tag.trim().toLowerCase();
    if (trimmedTag && !tags.includes(trimmedTag)) {
      const newTags = [...tags, trimmedTag];
      setTags(newTags);
      onUpdate(request.id, notes, newTags);
    }
    setNewTag('');
  };

  const handleRemoveTag = (tagToRemove: string) => {
    const newTags = tags.filter(tag => tag !== tagToRemove);
    setTags(newTags);
    onUpdate(request.id, notes, newTags);
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      if (newTag.trim()) {
        handleAddTag(newTag);
      } else {
        handleSave();
      }
    }
  };

  const getTagColor = (tag: string): string => {
    const tagColors: Record<string, string> = {
      'vulnerable': '#e74c3c',
      'interesting': '#f39c12',
      'api': '#3498db',
      'auth': '#9b59b6',
      'sensitive': '#e67e22',
      'error': '#c0392b',
      'slow': '#d35400',
      'large': '#16a085',
      'xss': '#e74c3c',
      'sqli': '#c0392b',
      'csrf': '#e67e22',
      'ssrf': '#d35400',
      'rce': '#c0392b',
      'lfi': '#a93226',
      'rfi': '#922b21',
    };
    return tagColors[tag.toLowerCase()] || '#007acc';
  };

  const [statusFilter, setStatusFilter] = useState<FindingStatus | 'all'>('all');
  const parsedFindings = parseFindingBlocks(notes || '');
  const findingBlocksFiltered = parsedFindings.filter(
    (f) => statusFilter === 'all' || f.status === statusFilter
  );
  const hasFindings = parsedFindings.length > 0;

  const updateFindingStatus = (blockIndex: number, newStatus: FindingStatus) => {
    const parsed = parseFindingBlocks(notes || '');
    const item = parsed[blockIndex];
    if (!item) return;
    const newBlock = setStatusInBlock(item.block, newStatus);
    const sep = '\n\n' + '='.repeat(60) + '\n\n';
    const parts = (notes || '').split(/\n={60,}\n\n/);
    if (parts.length <= blockIndex) return;
    parts[blockIndex] = newBlock;
    const newNotes = parts.join(sep);
    setNotes(newNotes);
    onUpdate(request.id, newNotes, tags);
  };

  const handleCopyNotes = () => {
    if (!notes) return;
    navigator.clipboard.writeText(notes);
  };

  const handleExportNotes = () => {
    if (!notes) return;
    const blob = new Blob([notes], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `notes-${request.url?.replace(/[^a-z0-9]/gi, '-').slice(0, 40) || 'export'}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="notes-tags-container">
      <div className="notes-section">
        <div className="section-header">
          <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
            <path d="M2 2H16C16.5523 2 17 2.44772 17 3V15C17 15.5523 16.5523 16 16 16H2C1.44772 16 1 15.5523 1 15V3C1 2.44772 1.44772 2 2 2Z" stroke="currentColor" strokeWidth="1.5" fill="none"/>
            <path d="M5 5H13M5 9H13M5 13H10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
          </svg>
          <h3>Notes</h3>
          <div className="notes-actions-row">
            {notes && (
              <>
                <button type="button" className="notes-action-btn" onClick={handleCopyNotes} title="Copy notes">
                  Copy
                </button>
                <button type="button" className="notes-action-btn" onClick={handleExportNotes} title="Export as .txt">
                  Export
                </button>
              </>
            )}
            {isEditing && (
              <button type="button" className="save-btn" onClick={handleSave}>
                <svg width="14" height="14" viewBox="0 0 14 14" fill="none">
                  <path d="M11.5 3.5L5.5 9.5L2.5 6.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
                </svg>
                Save
              </button>
            )}
          </div>
        </div>
        {hasFindings && (
          <div className="findings-lifecycle">
            <div className="findings-lifecycle-header">
              <span className="findings-badge">{parsedFindings.length} finding{parsedFindings.length !== 1 ? 's' : ''} from Scanner</span>
              <span className="findings-hint">Track status below. Use &quot;Send to Notes&quot; in Scanner to add more.</span>
            </div>
            <div className="findings-status-filter">
              <span className="filter-label">Status:</span>
              {(['all', ...FINDING_STATUSES] as const).map((s) => (
                <button
                  key={s}
                  type="button"
                  className={`findings-filter-btn ${statusFilter === s ? 'active' : ''}`}
                  onClick={() => setStatusFilter(s)}
                >
                  {s === 'all' ? 'All' : s === 'false positive' ? 'FP' : s}
                </button>
              ))}
            </div>
            <div className="findings-cards">
              {findingBlocksFiltered.map((f) => (
                <div key={f.index} className="finding-card">
                  <div className="finding-card-head">
                    <span className="finding-rule">{f.ruleId || 'Finding'}</span>
                    {f.severity && <span className="finding-severity">{f.severity}</span>}
                  </div>
                  <div className="finding-card-status">
                    <label className="finding-status-label">Status</label>
                    <select
                      className="finding-status-select"
                      value={f.status}
                      onChange={(e) => updateFindingStatus(f.index, e.target.value as FindingStatus)}
                    >
                      {FINDING_STATUSES.map((st) => (
                        <option key={st} value={st}>{st === 'false positive' ? 'False positive' : st}</option>
                      ))}
                    </select>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
        <textarea
          className="notes-input"
          placeholder="Add notes about this request (e.g., vulnerability details, testing notes, observations)..."
          value={notes}
          onChange={(e) => handleNotesChange(e.target.value)}
          onBlur={handleSave}
          rows={4}
        />
        {notes && (
          <div className="notes-preview">
            <div className="notes-count">{notes.length} characters</div>
          </div>
        )}
      </div>

      <div className="tags-section">
        <div className="section-header">
          <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
            <path d="M3 2H9L11 8L6 13L2 9L3 2Z" stroke="currentColor" strokeWidth="1.5" fill="none"/>
            <path d="M11 8L15 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
          </svg>
          <h3>Tags</h3>
        </div>
        
        <div className="tags-display">
          {tags.map((tag, index) => (
            <span
              key={index}
              className="tag-badge"
              style={{ backgroundColor: getTagColor(tag) }}
            >
              {tag}
              <button
                type="button"
                className="tag-remove"
                onClick={() => handleRemoveTag(tag)}
                aria-label={`Remove ${tag} tag`}
              >
                ×
              </button>
            </span>
          ))}
        </div>

        <div className="tags-input-section">
          <div className="input-with-suggestions">
            <input
              type="text"
              className="tag-input"
              placeholder="Add tag (press Enter)..."
              value={newTag}
              onChange={(e) => setNewTag(e.target.value)}
              onKeyPress={handleKeyPress}
              list="tag-suggestions"
            />
            <datalist id="tag-suggestions">
              {suggestedTags
                .filter(tag => !tags.includes(tag.toLowerCase()))
                .map((tag, index) => (
                  <option key={index} value={tag} />
                ))}
            </datalist>
            <button
              type="button"
              className="add-tag-btn"
              onClick={() => handleAddTag(newTag)}
              disabled={!newTag.trim()}
            >
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
                <path d="M8 3V13M3 8H13" stroke="currentColor" strokeWidth="2" strokeLinecap="round"/>
              </svg>
            </button>
          </div>
          
          <div className="suggested-tags">
            <span className="suggested-label">Quick add:</span>
            {suggestedTags
              .filter(tag => !tags.includes(tag.toLowerCase()))
              .slice(0, 8)
              .map((tag, index) => (
                <button
                  type="button"
                  key={index}
                  className="suggested-tag-btn"
                  onClick={() => handleAddTag(tag)}
                  style={{ '--tag-color': getTagColor(tag) } as React.CSSProperties}
                >
                  {tag}
                </button>
              ))}
          </div>
        </div>
      </div>
    </div>
  );
};

export default NotesTags;

