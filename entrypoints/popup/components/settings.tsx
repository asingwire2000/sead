
'use client';

import {
    ShieldAlert,
    Bug,
    Info,
    ChevronDown,
    Cog,
} from 'lucide-react';
import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

const appsettings = [
    {
        label: 'Block High-Risk Links',
        icon: <ShieldAlert className="h-5 w-5 text-systemRed" />,
        onClick: () => alert('Blocking High-Risk Links...'),
    },
];


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

export default function SettingsButton() {
    const [open, setOpen] = useState(false);

    return (
        <div className="relative inline-block text-left">
            {/* Trigger */}
            <div
                className={`flex items-center space-x-1 cursor-pointer  p-1 rounded-lg hover:bg-backgroundLayer2 ${open ? 'bg-backgroundLayer2' : ''}`}
                onClick={() => setOpen(prev => !prev)}
            >
                <Cog className='text-systemBlue hover:text-tintBlue' />
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
                        <div className="py-1 px-2">
                            {appsettings.map(({ label, icon, onClick }) => (
                                <motion.button
                                    key={label}
                                    onClick={() => {
                                        onClick();
                                        setOpen(false);
                                    }}
                                    className="flex w-full items-center gap-3 rounded-lg px-2 py-1 text-sm font-medium text-left hover:bg-backgroundLayer1 hover:shadow-md transition-all"
                                /* whileHover={{ scale: 1.03 }}
                                 whileTap={{ scale: 0.97 }}*/
                                >
                                    {icon}
                                    <span>{label}</span>
                                </motion.button>
                            ))}
                            <div className="my-2 h-px w-full bg-separator" />

                            {
                                feedsettings.map(({ label, icon, onClick }) => (
                                    <motion.button
                                        key={label}
                                        onClick={() => {
                                            onClick();
                                            setOpen(false);
                                        }}
                                        className="flex w-full items-center gap-3 rounded-lg px-2 py-2 text-sm font-medium text-left hover:bg-backgroundLayer1 hover:shadow-md transition-all"
                                    /* whileHover={{ scale: 1.03 }}
                                     whileTap={{ scale: 0.97 }}*/
                                    >
                                        {icon}
                                        <span>{label}</span>
                                    </motion.button>
                                ))
                            }
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
}
