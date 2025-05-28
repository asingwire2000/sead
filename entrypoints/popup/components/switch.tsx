import { useState } from 'react';

export default function Switch({ checked, onChange }: { checked: boolean, onChange: (value: boolean) => void }) {
  return (
    <div
      onClick={() => onChange(!checked)}
      className={`w-10 h-6 flex items-center bg-gray-300 rounded-full p-1 cursor-pointer transition-colors duration-300 ${
        checked ? 'bg-systemGreen' : 'bg-gray1'
      }`}
    >
      <div
        className={`bg-white w-4 h-4 rounded-full shadow-lg transform transition-transform duration-300 ${
          checked ? 'translate-x-4' : ''
        }`}
      ></div>
    </div>
  );
}
