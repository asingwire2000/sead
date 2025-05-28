'use client';

import { Bug, Info, Cog } from 'lucide-react';
import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import Switch from './switch';

const feedsettings = [
  {
    label: 'Report a Bug',
    icon: <Bug className="h-5 w-5 text-systemBlue" />,
    onClick: () => alert('Reporting Bug...'),
  },
  {
    label: 'About',
    icon: <Info className="h-5 w-5 text-systemBlue" />,
    onClick: () => alert('About This Extension...'),
  },
];

export default function SettingsButton({
  blockHighRiskLinks,
  setBlockHighRiskLinks,
}: {
  blockHighRiskLinks: boolean;
  setBlockHighRiskLinks: (value: boolean) => void;
}) {
  const [open, setOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  // 🧙‍♂️ Close on outside click
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    }

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  return (
    <div className="relative inline-block text-left" ref={menuRef}>
      {/* Trigger */}
      <div
        className={`flex items-center space-x-1 cursor-pointer p-1 rounded-lg hover:bg-backgroundLayer2 ${open ? 'bg-backgroundLayer2' : ''}`}
        onClick={() => setOpen(prev => !prev)}
      >
        <Cog className="text-systemBlue hover:text-tintBlue" />
      </div>

      {/* Dropdown Panel */}
      <AnimatePresence>
        {open && (
          <motion.div
            key="settings-menu"
            initial={{ opacity: 0, y: -12, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -12, scale: 0.95 }}
            transition={{ type: 'spring', stiffness: 200, damping: 25 }}
            className="absolute right-1 z-10 mt-2 w-64 origin-top-right rounded-2xl bg-background shadow-2xl ring-1 ring-separator"
          >
            <div className="py-1 px-1">
              <button
                onClick={() => setBlockHighRiskLinks(!blockHighRiskLinks)}
                className="flex w-full items-center gap-3 rounded-lg px-2 py-1 text-sm font-medium text-left transition-all justify-between"
              >
                <span>Block High-Risk Links</span>
                <Switch checked={blockHighRiskLinks} onChange={() => {}} />
              </button>

              <div className="my-2 h-px w-full bg-separator" />

              {feedsettings.map(({ label, icon, onClick }) => (
                <motion.button
                  key={label}
                  onClick={() => {
                    onClick();
                    setOpen(false);
                  }}
                  className="flex w-full items-center gap-3 rounded-lg px-2 py-2 text-sm font-medium text-left hover:bg-backgroundLayer1 hover:shadow-md transition-all"
                >
                  {icon}
                  <span>{label}</span>
                </motion.button>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
