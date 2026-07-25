import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import AsyncStorage from '@react-native-async-storage/async-storage';

// Definicja modelu wiadomości E2EE po odszyfrowaniu
export interface DecryptedMessage {
  id: string;
  senderId: string;
  text: string;
  timestamp: number;
}

interface VextroState {
  userId: string | null;
  serverIp: string | null;
  isEnclaveReady: boolean;
  messages: DecryptedMessage[];
  
  // Akcje
  setCredentials: (userId: string, serverIp: string) => void;
  setEnclaveReady: (status: boolean) => void;
  addMessage: (msg: DecryptedMessage) => void;
  clearSession: () => void;
}

export const useVextroStore = create<VextroState>()(
  persist(
    (set) => ({
      userId: null,
      serverIp: null,
      isEnclaveReady: false,
      messages: [],

      setCredentials: (userId, serverIp) => set({ userId, serverIp }),
      setEnclaveReady: (status) => set({ isEnclaveReady: status }),
      addMessage: (msg) => set((state) => ({ messages: [...state.messages, msg] })),
      clearSession: () => set({ userId: null, serverIp: null, isEnclaveReady: false, messages: [] }),
    }),
    {
      name: 'vextro-secure-storage', // Unikalny klucz w AsyncStorage
      storage: createJSONStorage(() => AsyncStorage),
      // Nie chcemy zapisywać stanu `isEnclaveReady`, bo przy każdym restarcie aplikacji
      // silnik E2EE musi na nowo załadować klucze z RAM-u i połączyć się przez WebSocket.
      partialize: (state) => ({ 
        userId: state.userId, 
        serverIp: state.serverIp,
        messages: state.messages 
      }),
    }
  )
);